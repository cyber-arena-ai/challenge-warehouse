"""Small stdlib/OpenSSL client for Nginx UI's native workflows."""

from __future__ import annotations

import base64
import binascii
import configparser
import hashlib
import hmac
import http.client
import io
import json
import re
import secrets
import sqlite3
import struct
import subprocess
import tempfile
import time
from typing import NamedTuple
import zipfile
import zlib


SERVICE_PORT = 9000
_NATIVE_ZIP_CREATOR_VERSION = (3 << 8) | 20
_NATIVE_ZIP_READER_VERSION = 20
_NATIVE_ZIP_FLAGS = 8


class BackupEntry(NamedTuple):
    crc32: int
    compressed_size: int
    uncompressed_size: int
    compression_method: int
    flags: int
    local_offset: int
    reader_version: int


class BackupManifest(NamedTuple):
    nginx_ui_hash: str
    nginx_hash: str
    timestamp: str
    version: str


class BackupPayload(NamedTuple):
    manifest: BackupManifest
    nginx: bytes


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return (
            response.status,
            {key.lower(): value for key, value in response.getheaders()},
            response.read(),
        )
    finally:
        connection.close()


def json_request(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict]:
    request_headers = dict(headers or {})
    body = None
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
        body = json.dumps(payload, separators=(",", ":")).encode()
    status, _, raw = request(
        host, port, method, path, body=body, headers=request_headers
    )
    try:
        value = json.loads(raw) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Nginx UI returned malformed JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("Nginx UI returned non-object JSON")
    return status, value


def _openssl(arguments: list[str], content: bytes) -> bytes:
    completed = subprocess.run(
        ["openssl", *arguments],
        input=content,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("OpenSSL operation failed")
    return completed.stdout


def encrypted_payload(host: str, port: int, values: dict[str, str]) -> dict[str, str]:
    status, document = json_request(
        host,
        port,
        "POST",
        "/api/crypto/public_key",
        payload={
            "timestamp": int(time.time() * 1000),
            "fingerprint": secrets.token_hex(16),
        },
    )
    public_key = document.get("public_key")
    if status != 200 or not isinstance(public_key, str) or not public_key:
        raise RuntimeError(f"Nginx UI public-key request returned HTTP {status}")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as key_file:
        key_file.write(public_key)
        key_file.flush()
        encrypted = _openssl(
            [
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey",
                key_file.name,
                "-pkeyopt",
                "rsa_padding_mode:pkcs1",
            ],
            json.dumps(values, separators=(",", ":")).encode(),
        )
    return {"encrypted_params": base64.b64encode(encrypted).decode()}


def login(host: str, port: int, username: str, password: str) -> str:
    status, document = json_request(
        host,
        port,
        "POST",
        "/api/login",
        payload=encrypted_payload(host, port, {"name": username, "password": password}),
    )
    token = document.get("token")
    if (
        status != 200
        or document.get("code") != 200
        or not isinstance(token, str)
        or not token
    ):
        raise RuntimeError(f"Nginx UI login returned HTTP {status}")
    return token


def fetch_backup(host: str, port: int, token: str | None = None) -> tuple[bytes, bytes, bytes, str]:
    headers = {"Authorization": token} if token else None
    status, response_headers, body = request(
        host, port, "GET", "/api/backup", headers=headers
    )
    if status != 200:
        raise PermissionError(status)
    key, iv, security = _backup_security(response_headers)
    return body, key, iv, security


def _backup_security(response_headers: dict[str, str]) -> tuple[bytes, bytes, str]:
    security = response_headers.get("x-backup-security", "")
    if ":" not in security:
        raise RuntimeError("Nginx UI backup omitted decryption material")
    encoded_key, encoded_iv = security.split(":", 1)
    try:
        key = base64.b64decode(encoded_key, validate=True)
        iv = base64.b64decode(encoded_iv, validate=True)
    except ValueError as error:
        raise RuntimeError("Nginx UI backup returned malformed decryption material") from error
    if len(key) != 32 or len(iv) != 16:
        raise RuntimeError("Nginx UI backup returned invalid AES material")
    return key, iv, security


def _read_exact(response: http.client.HTTPResponse, size: int) -> bytes:
    content = response.read(size)
    if len(content) != size:
        raise RuntimeError("Nginx UI backup body truncated")
    return content


def _parse_backup_manifest(
    encrypted: bytes, key: bytes | bytearray, iv: bytes | bytearray
) -> BackupManifest:
    manifest = decrypt_backup_part(encrypted, key, iv)
    try:
        lines = manifest.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("Nginx UI backup manifest malformed") from error
    expected_fields = {"nginx-ui_hash", "nginx_hash", "timestamp", "version"}
    fields: dict[str, str] = {}
    for line in lines:
        if not line:
            continue
        name, separator, value = line.partition(": ")
        if (
            not separator
            or name not in expected_fields
            or name in fields
        ):
            raise RuntimeError("Nginx UI backup manifest malformed")
        fields[name] = value
    if set(fields) != expected_fields:
        raise RuntimeError("Nginx UI backup manifest malformed")
    nginx_ui_hash = fields.get("nginx-ui_hash", "")
    nginx_hash = fields.get("nginx_hash", "")
    timestamp = fields.get("timestamp", "")
    version = fields.get("version", "")
    if (
        len(nginx_ui_hash) != 64
        or any(character not in "0123456789abcdef" for character in nginx_ui_hash)
        or len(nginx_hash) != 64
        or any(character not in "0123456789abcdef" for character in nginx_hash)
        or len(timestamp) != 15
        or timestamp[8] != "-"
        or not (timestamp[:8] + timestamp[9:]).isdigit()
        or not version
    ):
        raise RuntimeError("Nginx UI backup manifest fields malformed")
    return BackupManifest(nginx_ui_hash, nginx_hash, timestamp, version)


def _decrypt_backup_range(
    content: bytes,
    key: bytes | bytearray,
    iv: bytes | bytearray,
    offset: int,
    size: int,
) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(content):
        raise RuntimeError("Nginx UI private backup range invalid")
    if size == 0:
        return b""
    block_start = offset // 16 * 16
    block_end = (offset + size + 15) // 16 * 16
    range_iv = iv if block_start == 0 else content[block_start - 16 : block_start]
    decrypted = _openssl(
        [
            "enc",
            "-d",
            "-aes-256-cbc",
            "-nopad",
            "-K",
            key.hex(),
            "-iv",
            range_iv.hex(),
        ],
        content[block_start:block_end],
    )
    start = offset - block_start
    return decrypted[start : start + size]


def _encrypted_zip_catalog(
    content: bytes, key: bytes | bytearray, iv: bytes | bytearray
) -> tuple[dict[str, BackupEntry], int]:
    if not content or len(content) % 16 != 0:
        raise RuntimeError("Nginx UI private backup encryption malformed")
    last_block = _decrypt_backup_range(content, key, iv, len(content) - 16, 16)
    padding = last_block[-1]
    if (
        padding < 1
        or padding > 16
        or last_block[-padding:] != bytes([padding]) * padding
    ):
        raise RuntimeError("Nginx UI private backup padding malformed")
    plaintext_size = len(content) - padding
    if plaintext_size < 22:
        raise RuntimeError("Nginx UI private backup truncated")
    entry_count, directory_size, directory_offset = _backup_eocd(
        _decrypt_backup_range(content, key, iv, plaintext_size - 22, 22)
    )
    if (
        entry_count != 2
        or directory_size <= 0
        or directory_offset + directory_size != plaintext_size - 22
    ):
        raise RuntimeError("Nginx UI private backup directory changed")
    directory = _decrypt_backup_range(
        content, key, iv, directory_offset, directory_size
    )
    return _parse_backup_directory(directory), directory_offset


def _encrypted_zip_member_offset(
    content: bytes,
    key: bytes | bytearray,
    iv: bytes | bytearray,
    name: str,
    entry: BackupEntry,
    maximum_size: int,
    *,
    read_name: bool = True,
) -> int:
    header = _decrypt_backup_range(content, key, iv, entry.local_offset, 30)
    (
        signature,
        reader_version,
        flags,
        compression_method,
        _modified_time,
        _modified_date,
        local_crc32,
        local_compressed_size,
        local_uncompressed_size,
        name_size,
        extra_size,
    ) = struct.unpack("<4s5H3I2H", header)
    if (
        signature != b"PK\x03\x04"
        or reader_version != _NATIVE_ZIP_READER_VERSION
        or flags != _NATIVE_ZIP_FLAGS
        or compression_method != 8
        or local_crc32 != 0
        or local_compressed_size != 0
        or local_uncompressed_size != 0
        or name_size != len(name.encode("utf-8"))
        or entry.reader_version != reader_version
        or entry.flags != flags
        or entry.compression_method != compression_method
        or entry.uncompressed_size > maximum_size
    ):
        raise RuntimeError("Nginx UI private backup member encoding changed")
    if read_name:
        encoded_name = _decrypt_backup_range(
            content, key, iv, entry.local_offset + 30, name_size
        )
        try:
            local_name = encoded_name.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("Nginx UI private backup member name malformed") from error
        if local_name != name:
            raise RuntimeError("Nginx UI private backup directory inconsistent")
    return entry.local_offset + 30 + name_size + extra_size


def _encrypted_zip_member(
    content: bytes,
    key: bytes | bytearray,
    iv: bytes | bytearray,
    name: str,
    entry: BackupEntry,
    maximum_size: int,
) -> bytes:
    data_offset = _encrypted_zip_member_offset(
        content, key, iv, name, entry, maximum_size
    )
    compressed = _decrypt_backup_range(
        content, key, iv, data_offset, entry.compressed_size
    )
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    value = decoder.decompress(compressed, maximum_size + 1)
    if decoder.unconsumed_tail or len(value) > maximum_size:
        raise RuntimeError("Nginx UI private backup member oversized")
    value += decoder.flush()
    if (
        not decoder.eof
        or decoder.unused_data
        or len(value) != entry.uncompressed_size
        or len(value) > maximum_size
        or binascii.crc32(value) & 0xFFFFFFFF != entry.crc32
    ):
        raise RuntimeError("Nginx UI private backup member corrupt")
    return value


def _validate_private_app_identity(
    content: bytes,
    key: bytes | bytearray,
    iv: bytes | bytearray,
    entry: BackupEntry,
    token: str,
) -> None:
    data_offset = _encrypted_zip_member_offset(
        content, key, iv, "app.ini", entry, 256 * 1024
    )
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    prefix = bytearray()
    cursor = 0
    while cursor < entry.compressed_size and len(prefix) < 512:
        size = min(128, entry.compressed_size - cursor)
        compressed = _decrypt_backup_range(
            content, key, iv, data_offset + cursor, size
        )
        prefix.extend(decoder.decompress(compressed, 512 - len(prefix)))
        cursor += size
        if b"\n[server]\n" in prefix:
            break
    app_end = prefix.find(b"\n[server]\n")
    if app_end <= 0 or b"\n[node]\n" in prefix[:app_end]:
        raise RuntimeError("Nginx UI private app configuration malformed")
    app_section = bytes(prefix[:app_end])
    jwt = re.search(
        rb"(?m)^JwtSecret\s*=\s*([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
        rb"[89ab][0-9a-f]{3}-[0-9a-f]{12})\s*$",
        app_section,
    )
    if jwt is None or not re.search(rb"(?m)^PageSize\s*=\s*[1-9][0-9]*\s*$", app_section):
        raise RuntimeError("Nginx UI private app configuration malformed")
    parts = token.split(".")
    if len(parts) != 3:
        raise RuntimeError("Nginx UI login token malformed")
    try:
        header = json.loads(
            base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
        )
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Nginx UI login token malformed") from error
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        raise RuntimeError("Nginx UI login token algorithm changed")
    expected = base64.urlsafe_b64encode(
        hmac.new(
            jwt.group(1),
            f"{parts[0]}.{parts[1]}".encode(),
            hashlib.sha256,
        ).digest()
    ).decode().rstrip("=")
    if not hmac.compare_digest(expected, parts[2]):
        raise RuntimeError("Nginx UI private app configuration is not live")


def _validate_private_backup(
    encrypted: bytes,
    key: bytes | bytearray,
    iv: bytes | bytearray,
    *,
    user_id: int,
    username: str,
    language: str,
    token: str,
) -> None:
    catalog, directory_offset = _encrypted_zip_catalog(encrypted, key, iv)
    if set(catalog) != {"app.ini", "database.db"}:
        raise RuntimeError("Nginx UI private backup contents changed")
    app_entry = catalog["app.ini"]
    database_entry = catalog["database.db"]
    if (
        app_entry.local_offset != 0
        or app_entry.uncompressed_size == 0
        or app_entry.compressed_size == 0
        or database_entry.local_offset <= app_entry.local_offset
        or database_entry.uncompressed_size == 0
        or database_entry.compressed_size == 0
        or directory_offset <= database_entry.local_offset
    ):
        raise RuntimeError("Nginx UI private backup layout changed")
    _validate_private_app_identity(encrypted, key, iv, app_entry, token)
    app_data_offset = _encrypted_zip_member_offset(
        encrypted,
        key,
        iv,
        "app.ini",
        app_entry,
        256 * 1024,
        read_name=False,
    )
    if (
        app_data_offset + app_entry.compressed_size + 16
        != database_entry.local_offset
    ):
        raise RuntimeError("Nginx UI private backup layout changed")
    database = _encrypted_zip_member(
        encrypted, key, iv, "database.db", database_entry, 32 * 1024 * 1024
    )
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(database)
        row = connection.execute(
            "SELECT name, language, status, deleted_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    except sqlite3.Error as error:
        raise RuntimeError("Nginx UI private backup database malformed") from error
    finally:
        connection.close()
    if row != (username, language, 1, None):
        raise RuntimeError("Nginx UI private backup omitted fresh administrator state")


def _read_backup_member(
    response: http.client.HTTPResponse,
    maximum_size: int,
    local_offset: int,
    *,
    retain: bool,
) -> tuple[str, bytes | None, BackupEntry, int]:
    local_header = _read_exact(response, 30)
    (
        signature,
        reader_version,
        flags,
        compression_method,
        _modified_time,
        _modified_date,
        crc32,
        compressed_size,
        uncompressed_size,
        name_size,
        extra_size,
    ) = struct.unpack("<4s5H3I2H", local_header)
    if (
        signature != b"PK\x03\x04"
        or reader_version != _NATIVE_ZIP_READER_VERSION
        or flags != _NATIVE_ZIP_FLAGS
        or compression_method != 8
        or name_size <= 0
    ):
        raise RuntimeError("Nginx UI backup member encoding changed")
    try:
        name = _read_exact(response, name_size).decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("Nginx UI backup member name malformed") from error
    _read_exact(response, extra_size)

    retained = bytearray() if retain else None
    actual_size = 0
    computed_crc = 0
    descriptor_size = 0
    if flags & 8:
        if compression_method != 8:
            raise RuntimeError("Nginx UI backup member compression changed")
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        compressed_size = 0
        while not decoder.eof:
            chunk = _read_exact(response, 1)
            compressed_size += 1
            decoded = decoder.decompress(chunk)
            actual_size += len(decoded)
            if actual_size > maximum_size:
                raise RuntimeError("Nginx UI backup member oversized")
            computed_crc = binascii.crc32(decoded, computed_crc)
            if retained is not None:
                retained.extend(decoded)
        if decoder.unused_data:
            raise RuntimeError("Nginx UI backup member framing changed")
        descriptor = _read_exact(response, 16)
        descriptor_signature, crc32, described_size, uncompressed_size = struct.unpack(
            "<4s3I", descriptor
        )
        if descriptor_signature != b"PK\x07\x08" or described_size != compressed_size:
            raise RuntimeError("Nginx UI backup member descriptor malformed")
        descriptor_size = 16
    else:
        if compressed_size <= 0 or uncompressed_size > maximum_size:
            raise RuntimeError("Nginx UI backup member size malformed")
        decoder = (
            zlib.decompressobj(-zlib.MAX_WBITS)
            if compression_method == 8
            else None
        )
        remaining = compressed_size
        while remaining:
            chunk = _read_exact(response, min(65536, remaining))
            remaining -= len(chunk)
            decoded = decoder.decompress(chunk) if decoder is not None else chunk
            actual_size += len(decoded)
            if actual_size > maximum_size:
                raise RuntimeError("Nginx UI backup member oversized")
            computed_crc = binascii.crc32(decoded, computed_crc)
            if retained is not None:
                retained.extend(decoded)
        if decoder is not None and (not decoder.eof or decoder.unused_data):
            raise RuntimeError("Nginx UI backup member framing changed")

    if (
        actual_size != uncompressed_size
        or computed_crc & 0xFFFFFFFF != crc32
    ):
        raise RuntimeError("Nginx UI backup member corrupt")
    entry = BackupEntry(
        crc32,
        compressed_size,
        uncompressed_size,
        compression_method,
        flags,
        local_offset,
        reader_version,
    )
    consumed = 30 + name_size + extra_size + compressed_size + descriptor_size
    content = bytes(retained) if retained is not None else None
    return name, content, entry, consumed


def fetch_backup_payload(
    host: str,
    port: int,
    token: str,
    *,
    private_user: tuple[int, str, str],
) -> BackupPayload:
    """Validate one complete backup without decrypting its private app.ini."""
    connection = http.client.HTTPConnection(host, port, timeout=30)
    key: bytearray | None = None
    iv: bytearray | None = None
    try:
        connection.request("GET", "/api/backup", headers={"Authorization": token})
        response = connection.getresponse()
        status = response.status
        headers = {key.lower(): value for key, value in response.getheaders()}
        if status != 200:
            raise PermissionError(status)
        key_bytes, iv_bytes, security = _backup_security(headers)
        key = bytearray(key_bytes)
        iv = bytearray(iv_bytes)
        del key_bytes, iv_bytes
        headers.pop("x-backup-security", None)
        response_headers = getattr(response, "headers", None)
        if response_headers is not None:
            del response_headers["X-Backup-Security"]
        try:
            content_length = int(headers.get("content-length", "0"))
        except ValueError as error:
            raise RuntimeError("Nginx UI backup length malformed") from error
        if (
            headers.get("content-type") != "application/zip"
            or "attachment" not in headers.get("content-disposition", "")
            or content_length <= 0
            or content_length > 128 * 1024 * 1024
        ):
            raise RuntimeError("Nginx UI full backup response malformed")

        manifest_name, encrypted_manifest, manifest_entry, manifest_size = (
            _read_backup_member(response, 4096, 0, retain=True)
        )
        nginx_name, encrypted_nginx, nginx_entry, nginx_size = _read_backup_member(
            response, 32 * 1024 * 1024, manifest_size, retain=True
        )
        if (
            manifest_name != "hash_info.txt"
            or nginx_name != "nginx.zip"
            or encrypted_manifest is None
            or encrypted_nginx is None
        ):
            raise RuntimeError("Nginx UI backup proof-free prefix changed")
        manifest = _parse_backup_manifest(encrypted_manifest, key, iv)
        nginx = decrypt_backup_part(encrypted_nginx, key, iv)

        private_offset = manifest_size + nginx_size
        private_name, encrypted_private, private_entry, private_size = (
            _read_backup_member(
                response,
                64 * 1024 * 1024,
                private_offset,
                retain=True,
            )
        )
        directory_offset = private_offset + private_size
        directory_response_size = content_length - directory_offset
        if (
            private_name != "nginx-ui.zip"
            or private_entry.uncompressed_size == 0
            or private_entry.uncompressed_size % 16 != 0
            or directory_response_size < 22
            or directory_response_size > 65536
        ):
            raise RuntimeError("Nginx UI private backup envelope changed")
        directory_response = _read_exact(response, directory_response_size)
        if response.read(1):
            raise RuntimeError("Nginx UI backup length inconsistent")
        entry_count, directory_size, described_offset = _backup_eocd(
            directory_response[-22:]
        )
        directory = directory_response[:-22]
        if (
            entry_count != 3
            or directory_size != len(directory)
            or described_offset != directory_offset
        ):
            raise RuntimeError("Nginx UI backup directory changed")
        catalog = _parse_backup_directory(directory)
        expected = {
            manifest_name: manifest_entry,
            nginx_name: nginx_entry,
            private_name: private_entry,
        }
        if catalog != expected:
            raise RuntimeError("Nginx UI backup directory inconsistent")
        if encrypted_private is None:
            raise RuntimeError("Nginx UI private backup unavailable")
        user_id, username, language = private_user
        _validate_private_backup(
            encrypted_private,
            key,
            iv,
            user_id=user_id,
            username=username,
            language=language,
            token=token,
        )
        validate_backup(
            host,
            port,
            token,
            {
                manifest_name: encrypted_manifest,
                nginx_name: encrypted_nginx,
                private_name: encrypted_private,
            },
            security,
        )
        return BackupPayload(manifest, nginx)
    finally:
        if key is not None:
            key[:] = b"\0" * len(key)
        if iv is not None:
            iv[:] = b"\0" * len(iv)
        connection.close()


def _backup_eocd(content: bytes) -> tuple[int, int, int]:
    if len(content) != 22:
        raise RuntimeError("Nginx UI backup end record changed")
    (
        signature,
        disk_number,
        directory_disk,
        disk_entries,
        total_entries,
        directory_size,
        directory_offset,
        comment_size,
    ) = struct.unpack("<4s4H2IH", content)
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or directory_disk != 0
        or disk_entries != total_entries
        or comment_size != 0
    ):
        raise RuntimeError("Nginx UI backup end record malformed")
    return total_entries, directory_size, directory_offset


def _parse_backup_directory(directory: bytes) -> dict[str, BackupEntry]:
    catalog: dict[str, BackupEntry] = {}
    cursor = 0
    while cursor < len(directory):
        if directory[cursor : cursor + 4] != b"PK\x01\x02" or cursor + 46 > len(
            directory
        ):
            raise RuntimeError("Nginx UI backup catalog malformed")
        creator_version, reader_version = struct.unpack_from(
            "<2H", directory, cursor + 4
        )
        crc32, compressed_size, uncompressed_size = struct.unpack_from(
            "<3I", directory, cursor + 16
        )
        flags, compression_method = struct.unpack_from("<2H", directory, cursor + 8)
        name_size, extra_size, comment_size = struct.unpack_from(
            "<3H", directory, cursor + 28
        )
        if (
            creator_version != _NATIVE_ZIP_CREATOR_VERSION
            or reader_version != _NATIVE_ZIP_READER_VERSION
        ):
            raise RuntimeError("Nginx UI backup ZIP version changed")
        local_offset = struct.unpack_from("<I", directory, cursor + 42)[0]
        next_cursor = cursor + 46 + name_size + extra_size + comment_size
        if next_cursor > len(directory):
            raise RuntimeError("Nginx UI backup catalog truncated")
        try:
            name = directory[cursor + 46 : cursor + 46 + name_size].decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("Nginx UI backup member name malformed") from error
        if name in catalog:
            raise RuntimeError("Nginx UI backup catalog duplicated a member")
        catalog[name] = BackupEntry(
            crc32,
            compressed_size,
            uncompressed_size,
            compression_method,
            flags,
            local_offset,
            reader_version,
        )
        cursor = next_cursor
    return catalog


def decrypt_backup_part(
    content: bytes, key: bytes | bytearray, iv: bytes | bytearray
) -> bytes:
    return _openssl(
        ["enc", "-d", "-aes-256-cbc", "-nosalt", "-K", key.hex(), "-iv", iv.hex()],
        content,
    )


def encrypt_backup_part(content: bytes, key: bytes, iv: bytes) -> bytes:
    return _openssl(
        ["enc", "-aes-256-cbc", "-nosalt", "-K", key.hex(), "-iv", iv.hex()],
        content,
    )


def _rewrite_zip(
    content: bytes,
    replacements: dict[str, bytes],
    *,
    keep: set[str] | None = None,
) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(content))
    output = io.BytesIO()
    with source, zipfile.ZipFile(output, "w") as destination:
        for info in source.infolist():
            if keep is not None and info.filename not in keep:
                continue
            destination.writestr(info, replacements.get(info.filename, source.read(info)))
    return output.getvalue()


def rewrite_node_credential(
    outer_archive: bytes,
    key: bytes,
    iv: bytes,
    *,
    node_name: str,
    node_secret: str,
) -> bytes:
    with zipfile.ZipFile(io.BytesIO(outer_archive)) as outer:
        encrypted_inner = outer.read("nginx-ui.zip")
    inner_archive = decrypt_backup_part(encrypted_inner, key, iv)
    with zipfile.ZipFile(io.BytesIO(inner_archive)) as inner:
        raw_config = inner.read("app.ini").decode("utf-8")
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(raw_config)
    if not parser.has_section("node"):
        parser.add_section("node")
    parser.set("node", "Name", node_name)
    parser.set("node", "Secret", node_secret)
    rendered = io.StringIO()
    parser.write(rendered, space_around_delimiters=True)
    new_inner = _rewrite_zip(
        inner_archive,
        {"app.ini": rendered.getvalue().encode("utf-8")},
        keep={"app.ini"},
    )
    return _rewrite_zip(
        outer_archive, {"nginx-ui.zip": encrypt_backup_part(new_inner, key, iv)}
    )


def _multipart(fields: dict[str, str], filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----cyberarena" + secrets.token_hex(16)
    body = bytearray()
    for name, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        body.extend(value.encode())
        body.extend(b"\r\n")
    body.extend(f"--{boundary}\r\n".encode())
    body.extend(
        (
            f'Content-Disposition: form-data; name="backup_file"; '
            f'filename="{filename}"\r\nContent-Type: application/zip\r\n\r\n'
        ).encode()
    )
    body.extend(content)
    body.extend(f"\r\n--{boundary}--\r\n".encode())
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _restore_backup(
    host: str,
    port: int,
    token: str,
    archive: bytes,
    security: str,
    *,
    restore_nginx_ui: bool,
    verify_hash: bool,
) -> dict:
    body, content_type = _multipart(
        {
            "restore_nginx": "false",
            "restore_nginx_ui": str(restore_nginx_ui).lower(),
            "verify_hash": str(verify_hash).lower(),
            "security_token": security,
        },
        "backup.zip",
        archive,
    )
    status, _, raw = request(
        host,
        port,
        "POST",
        "/api/restore",
        body=body,
        headers={"Authorization": token, "Content-Type": content_type},
        timeout=60,
    )
    if status != 200:
        raise RuntimeError(f"Nginx UI restore returned HTTP {status}")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Nginx UI restore returned malformed JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("Nginx UI restore returned malformed JSON")
    return value


def restore_backup(
    host: str,
    port: int,
    token: str,
    archive: bytes,
    security: str,
) -> None:
    value = _restore_backup(
        host,
        port,
        token,
        archive,
        security,
        restore_nginx_ui=True,
        verify_hash=False,
    )
    if value.get("nginx_ui_restored") is not True:
        raise RuntimeError("Nginx UI restore did not restore application state")


def validate_backup(
    host: str,
    port: int,
    token: str,
    encrypted_parts: dict[str, bytes],
    security: str,
) -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as outer:
        for name in ("hash_info.txt", "nginx.zip", "nginx-ui.zip"):
            value = encrypted_parts.get(name)
            if value is None:
                raise RuntimeError("Nginx UI backup verification member unavailable")
            outer.writestr(name, value)
    result = _restore_backup(
        host,
        port,
        token,
        archive.getvalue(),
        security,
        restore_nginx_ui=False,
        verify_hash=True,
    )
    if (
        result.get("hash_match") is not True
        or result.get("nginx_ui_restored") is not False
        or result.get("nginx_restored") is not False
    ):
        raise RuntimeError("Nginx UI native backup verification failed")
