"""Defender-independent network checker for ownCloud's declared workflow."""

from __future__ import annotations

import base64
import datetime
import gzip
import hashlib
import http.client
import json
import secrets
import shlex
import urllib.parse
import zlib

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._health_identity import checker_identity_pool, open_issued_cohort


FACILITY_CLIENT = "/arena/facility_client.py"
_USER_AGENT_FAMILIES = (
    "aria2",
    "curl",
    "davfs2",
    "Mozilla",
    "ownCloud-client",
    "python-httpx",
    "python-requests",
    "rclone",
    "Wget",
)
_USER_AGENT_COMMENTS = (
    "X11; Linux x86_64",
    "Windows NT 10.0; Win64; x64",
    "compatible; ordinary client",
)
_USER_AGENT_MAJOR_RANGES = {
    "aria2": (1, 2),
    "curl": (7, 10),
    "davfs2": (1, 2),
    "Mozilla": (5, 6),
    "ownCloud-client": (3, 7),
    "python-httpx": (0, 2),
    "python-requests": (2, 3),
    "rclone": (1, 3),
    "Wget": (1, 2),
}
_COMMON_MEDIA_RANGES = (
    "application/json",
    "application/xhtml+xml",
    "application/xml",
    "image/avif",
    "image/webp",
    "text/html",
    "text/plain",
)
_COMMON_LANGUAGE_RANGES = (
    "*",
    "en",
    "en-US",
    "en-GB",
    "de-DE",
    "fr-FR",
    "es-ES",
    "zh-Hant-TW",
)
_COMMON_ENCODING_RANGES = (
    "gzip",
    "deflate",
    "identity",
)
_CONNECTION_OPTIONS = (
    "close",
    "keep-alive",
)
_TOKEN_CHARACTERS = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!#$%&'*+-.^_`|~"
)


def _list_separator() -> str:
    return (",", ", ", ",\t")[secrets.randbelow(3)]


def _join(values: list[str]) -> str:
    return values[0] + "".join(
        _list_separator() + value for value in values[1:]
    )


def _positive_quality() -> str:
    if secrets.randbelow(4) == 0:
        return ("1", "1.0", "1.00")[secrets.randbelow(3)]
    tenths = 1 + secrets.randbelow(9)
    if secrets.randbelow(2):
        return f"0.{tenths}{secrets.randbelow(10)}"
    return f"0.{tenths}"


def _with_quality(value: str) -> str:
    return f"{value};q={_positive_quality()}" if secrets.randbelow(2) else value


def _random_case(value: str) -> str:
    return "".join(
        character.upper()
        if character.isalpha() and secrets.randbelow(2)
        else character
        for character in value
    )


def _random_version(family: str) -> str:
    lower, upper = _USER_AGENT_MAJOR_RANGES.get(family, (1, 10))
    components = [str(lower + secrets.randbelow(upper - lower))]
    for _ in range(1 + secrets.randbelow(3)):
        components.append(str(secrets.randbelow(1000)))
    return ".".join(components)


def _random_product() -> str:
    if secrets.randbelow(2):
        return _USER_AGENT_FAMILIES[secrets.randbelow(len(_USER_AGENT_FAMILIES))]
    return "".join(
        _TOKEN_CHARACTERS[secrets.randbelow(len(_TOKEN_CHARACTERS))]
        for _ in range(1 + secrets.randbelow(32))
    )


def _random_user_agent() -> str:
    family = _random_product()
    version = _random_version(family)
    value = f"{family}/{version}"
    if secrets.randbelow(2):
        comment = _USER_AGENT_COMMENTS[
            secrets.randbelow(len(_USER_AGENT_COMMENTS))
        ]
        value += f" ({comment})"
    return value


def _response_compatible_range(media_type: str) -> str:
    media_family, _ = media_type.split("/", 1)
    bases = (
        (media_type, f"{media_family}/*", "*/*")
        if media_type != "*/*"
        else ("*/*",)
    )
    return _with_quality(_random_case(bases[secrets.randbelow(len(bases))]))


def _random_accept(media_type: str = "*/*") -> str:
    values = [_response_compatible_range(media_type)]
    for _ in range(secrets.randbelow(4)):
        value = _COMMON_MEDIA_RANGES[secrets.randbelow(len(_COMMON_MEDIA_RANGES))]
        values.append(_with_quality(_random_case(value)))
    anchor = values.pop(0)
    values.insert(secrets.randbelow(len(values) + 1), anchor)
    return _join(values)


def _random_accept_language() -> str:
    values = []
    for _ in range(1 + secrets.randbelow(3)):
        value = _COMMON_LANGUAGE_RANGES[
            secrets.randbelow(len(_COMMON_LANGUAGE_RANGES))
        ]
        values.append(_with_quality(value))
    return _join(values)


def _random_accept_encoding() -> str:
    values = []
    for _ in range(1 + secrets.randbelow(3)):
        value = _COMMON_ENCODING_RANGES[
            secrets.randbelow(len(_COMMON_ENCODING_RANGES))
        ]
        values.append(_with_quality(value))
    return _join(values)


def _random_connection() -> str:
    return _CONNECTION_OPTIONS[secrets.randbelow(len(_CONNECTION_OPTIONS))]


def _client_profile(media_type: str = "*/*") -> dict[str, str]:
    profile = {}
    generators = {
        "User-Agent": _random_user_agent,
        "Accept": lambda: _random_accept(media_type),
        "Accept-Language": _random_accept_language,
        "Accept-Encoding": _random_accept_encoding,
        "Connection": _random_connection,
    }
    for header, generator in generators.items():
        if secrets.randbelow(2):
            profile[header] = generator()
    return profile


def _request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: bytes | None = None,
    *,
    username: str | None = None,
    password: str | None = None,
    headers: dict[str, str] | None = None,
    profile: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    final_headers = dict(profile or {})
    if username is not None:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        final_headers["Authorization"] = f"Basic {token}"
    final_headers.update(headers or {})
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        connection.putrequest(method, path, skip_accept_encoding=True)
        if body is not None and "Content-Length" not in final_headers:
            final_headers["Content-Length"] = str(len(body))
        for header, value in final_headers.items():
            connection.putheader(header, value)
        connection.endheaders(body)
        response = connection.getresponse()
        response_body = response.read()
        encoding = (response.getheader("Content-Encoding") or "").lower()
        if encoding == "gzip":
            response_body = gzip.decompress(response_body)
        elif encoding == "deflate":
            response_body = zlib.decompress(response_body)
        return response.status, response_body
    finally:
        connection.close()


def _signed_path(
    host: str, port: int, path: str, username: str, key: str
) -> str:
    params = [
        ("OC-Credential", username),
        ("OC-Date", datetime.datetime.now(datetime.timezone.utc).isoformat()),
        ("OC-Expires", "300"),
        ("OC-Verb", "GET"),
    ]
    query = urllib.parse.urlencode(params)
    unsigned = f"http://{host}:{port}{path}?{query}"
    signature = hashlib.pbkdf2_hmac(
        "sha512", unsigned.encode(), key.encode(), 10000, dklen=32
    ).hex()
    return f"{path}?{query}&OC-Signature={signature}"


def _issued_principals(target: VulboxTarget) -> tuple[tuple[str, str], ...]:
    exec_in = target.meta.get("exec_in_container")
    if not callable(exec_in):
        raise RuntimeError("ownCloud issued principal bridge is unavailable")
    rc, output = exec_in(
        target.host,
        f"{shlex.quote(FACILITY_CLIENT)} read-issued-cohort",
    )
    if rc != 0:
        raise RuntimeError("ownCloud issued principal cohort is unavailable")
    return open_issued_cohort((output or "").strip())


class OwnCloudNetworkChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "owncloud-signed-url-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = target.host
        port = target.ports["service"]
        checks: list[tuple[str, bool, str]] = []
        try:
            participants = _issued_principals(target)
            checker_peers = checker_identity_pool(target)
            status, body = _request(
                host,
                port,
                "GET",
                "/status.php",
                profile=_client_profile("application/json"),
            )
            installed = status == 200 and json.loads(body).get("installed") is True
            checks.append(("protocol", installed, f"status={status}"))

            for index, (primary_user, primary_password) in enumerate(participants):
                peer_user, peer_password = (
                    participants[(index + 1) % len(participants)]
                    if len(participants) > 1
                    else checker_peers[index % len(checker_peers)]
                )
                document_id = secrets.token_hex(10)
                path = (
                    f"/remote.php/dav/files/{primary_user}/"
                    f"document-{document_id}.txt"
                )
                content = (
                    f"Project document {document_id}\n"
                    f"Updated {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
                ).encode()
                put_status, _ = _request(
                    host,
                    port,
                    "PUT",
                    path,
                    content,
                    username=primary_user,
                    password=primary_password,
                    profile=_client_profile(),
                )
                get_status, get_body = _request(
                    host,
                    port,
                    "GET",
                    path,
                    username=primary_user,
                    password=primary_password,
                    profile=_client_profile("text/plain"),
                )
                ordinary = (
                    put_status in {201, 204}
                    and get_status == 200
                    and get_body == content
                )
                checks.append(
                    ("ordinary-dav", ordinary, f"put={put_status},get={get_status}")
                )

                cross_status, cross_body = _request(
                    host,
                    port,
                    "GET",
                    path,
                    username=peer_user,
                    password=peer_password,
                    profile=_client_profile(),
                )
                isolated = cross_status in {401, 403, 404} and cross_body != content
                checks.append(("peer-isolation", isolated, f"status={cross_status}"))

                key_status, key_body = _request(
                    host,
                    port,
                    "GET",
                    "/ocs/v1.php/cloud/user/signing-key?format=json",
                    username=primary_user,
                    password=primary_password,
                    headers={"OCS-APIRequest": "true"},
                    profile=_client_profile("application/json"),
                )
                key = json.loads(key_body).get("ocs", {}).get("data", {}).get(
                    "signing-key"
                )
                if key_status == 200 and isinstance(key, str) and len(key) == 64:
                    signed_status, signed_body = _request(
                        host,
                        port,
                        "GET",
                        _signed_path(host, port, path, primary_user, key),
                        profile=_client_profile("text/plain"),
                    )
                else:
                    signed_status, signed_body = 0, b""
                signed_ok = signed_status == 200 and signed_body == content
                checks.append(("signed-url", signed_ok, f"status={signed_status}"))
        except Exception as error:
            return CheckResult(
                name="checker", passed=False, detail=f"{type(error).__name__}"
            )

        failures = [f"{name}({detail})" for name, passed, detail in checks if not passed]
        return CheckResult(
            name="checker",
            passed=not failures,
            detail=(
                "; ".join(failures)
                if failures
                else f"randomized DAV and signed URL workflow passed for {len(participants)} issued principals"
            ),
        )
