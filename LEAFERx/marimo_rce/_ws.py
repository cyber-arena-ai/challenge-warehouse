"""Small RFC 6455 client for marimo's terminal and editor probes."""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import time
import urllib.parse


class _Reader:
    def __init__(self, connection: socket.socket) -> None:
        self.connection = connection
        self.buffer = b""

    def exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            chunk = self.connection.recv(4096)
            if not chunk:
                raise EOFError("WebSocket closed")
            self.buffer += chunk
        value, self.buffer = self.buffer[:size], self.buffer[size:]
        return value

    def headers(self) -> bytes:
        while b"\r\n\r\n" not in self.buffer:
            chunk = self.connection.recv(4096)
            if not chunk:
                raise EOFError("WebSocket closed during handshake")
            self.buffer += chunk
        value, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
        return value

    def frame(self) -> tuple[int, bytes]:
        first, second = self.exact(2)
        size = second & 0x7F
        if size == 126:
            size = struct.unpack(">H", self.exact(2))[0]
        elif size == 127:
            size = struct.unpack(">Q", self.exact(8))[0]
        mask = self.exact(4) if second & 0x80 else b""
        payload = self.exact(size) if size else b""
        if mask:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return first & 0x0F, payload


def _frame(payload: bytes, *, opcode: int = 1) -> bytes:
    header = bytes([0x80 | opcode])
    size = len(payload)
    if size < 126:
        header += bytes([0x80 | size])
    elif size < 65536:
        header += bytes([0xFE]) + struct.pack(">H", size)
    else:
        header += bytes([0xFF]) + struct.pack(">Q", size)
    mask = os.urandom(4)
    return header + mask + bytes(
        byte ^ mask[index % 4] for index, byte in enumerate(payload)
    )


def _connect(
    host: str,
    port: int,
    path: str,
    *,
    authorization: str | None = None,
    timeout: float = 10,
) -> tuple[socket.socket, _Reader, int, str]:
    connection = socket.create_connection((host, port), timeout=timeout)
    connection.settimeout(timeout)
    reader = _Reader(connection)
    key = base64.b64encode(os.urandom(16)).decode()
    auth = f"Authorization: {authorization}\r\n" if authorization else ""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"{auth}\r\n"
    )
    connection.sendall(request.encode())
    status_line = reader.headers().decode(errors="replace").splitlines()[0]
    try:
        status = int(status_line.split()[1])
    except (IndexError, ValueError) as error:
        connection.close()
        raise RuntimeError("malformed WebSocket handshake") from error
    return connection, reader, status, status_line


def handshake_status(
    host: str, port: int, path: str, *, authorization: str | None = None
) -> int:
    connection, _, status, _ = _connect(
        host, port, path, authorization=authorization
    )
    try:
        if status == 101:
            connection.sendall(_frame(b"", opcode=8))
        return status
    finally:
        connection.close()


def editor_session(
    host: str,
    port: int,
    *,
    access_token: str,
    session_id: str,
) -> tuple[int, dict[str, object] | None]:
    """Open an authenticated editor session and return its initial document."""
    path = "/ws?" + urllib.parse.urlencode(
        {"access_token": access_token, "session_id": session_id}
    )
    connection, reader, status, _ = _connect(host, port, path)
    if status != 101:
        connection.close()
        return status, None
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                opcode, payload = reader.frame()
            except (EOFError, socket.timeout):
                break
            if opcode == 8:
                break
            if opcode == 9:
                connection.sendall(_frame(payload, opcode=10))
            elif opcode in (0, 1, 2) and payload:
                try:
                    message = json.loads(payload)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if (
                    isinstance(message, dict)
                    and message.get("op") == "kernel-ready"
                    and isinstance(message.get("data"), dict)
                ):
                    return status, message["data"]
        return status, None
    finally:
        try:
            connection.sendall(_frame(b"", opcode=8))
        except OSError:
            pass
        connection.close()


def terminal_command(
    host: str,
    port: int,
    command: str,
    marker: str,
    *,
    authorization: str | None = None,
    access_token: str | None = None,
) -> tuple[int, str]:
    path = "/terminal/ws"
    if access_token is not None:
        path += "?" + urllib.parse.urlencode({"access_token": access_token})
    connection, reader, status, _ = _connect(
        host, port, path, authorization=authorization
    )
    if status != 101:
        connection.close()
        return status, ""
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            opcode, payload = reader.frame()
            if opcode == 8:
                return status, ""
            if opcode == 9:
                connection.sendall(_frame(payload, opcode=10))
            elif opcode in (0, 1, 2) and b"$ " in payload:
                break
        else:
            return status, ""

        connection.sendall(_frame((command + "\n").encode()))
        output = ""
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                opcode, payload = reader.frame()
            except (EOFError, socket.timeout):
                break
            if opcode == 8:
                break
            if opcode in (0, 1, 2):
                output += payload.decode(errors="replace")
                after_echo = output.split("\r\n", 1)[-1]
                if "\r\n" in output and marker in after_echo:
                    break
        return status, output.split("\r\n", 1)[-1]
    finally:
        try:
            connection.sendall(_frame(b"", opcode=8))
        except OSError:
            pass
        connection.close()
