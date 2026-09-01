"""Small MQTT 3.1.1 client used by checker, handler, and private PoV."""

from __future__ import annotations

import ipaddress
import socket
import struct
import subprocess


class MqttError(RuntimeError):
    pass


def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", host],
            capture_output=True, text=True, timeout=5,
        )
        addresses = result.stdout.split()
        if addresses:
            return addresses[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return host


def _utf8(value: str) -> bytes:
    raw = value.encode()
    if len(raw) > 65535:
        raise ValueError("MQTT string too long")
    return struct.pack("!H", len(raw)) + raw


def _remaining_length(size: int) -> bytes:
    encoded = bytearray()
    while True:
        digit = size % 128
        size //= 128
        if size:
            digit |= 0x80
        encoded.append(digit)
        if not size:
            return bytes(encoded)


class MqttClient:
    def __init__(self, host: str, port: int, username: str, password: str,
                 *, client_id: str, timeout: float = 5.0) -> None:
        self.sock = socket.create_connection((resolve_host(host), port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._packet_id = 0
        self._queued: list[tuple[str, bytes, bool]] = []
        variable = _utf8("MQTT") + bytes((4, 0xC2)) + struct.pack("!H", 20)
        payload = _utf8(client_id) + _utf8(username) + _utf8(password)
        self._send(0x10, variable + payload)
        header, body = self._recv_packet()
        if header >> 4 != 2 or len(body) != 2 or body[1] != 0:
            code = body[1] if len(body) == 2 else -1
            self.close()
            raise MqttError(f"MQTT connection rejected: {code}")

    def _send(self, header: int, body: bytes) -> None:
        self.sock.sendall(bytes((header,)) + _remaining_length(len(body)) + body)

    def _read_exact(self, size: int) -> bytes:
        out = bytearray()
        while len(out) < size:
            part = self.sock.recv(size - len(out))
            if not part:
                raise MqttError("MQTT connection closed")
            out.extend(part)
        return bytes(out)

    def _recv_packet(self) -> tuple[int, bytes]:
        first = self._read_exact(1)[0]
        multiplier = 1
        remaining = 0
        for _ in range(4):
            digit = self._read_exact(1)[0]
            remaining += (digit & 0x7F) * multiplier
            if not digit & 0x80:
                return first, self._read_exact(remaining)
            multiplier *= 128
        raise MqttError("invalid remaining length")

    def _next_packet_id(self) -> int:
        self._packet_id = self._packet_id % 65535 + 1
        return self._packet_id

    def _decode_publish(self, header: int, body: bytes) -> tuple[str, bytes, bool]:
        if len(body) < 2:
            raise MqttError("short PUBLISH")
        topic_len = struct.unpack("!H", body[:2])[0]
        if len(body) < 2 + topic_len:
            raise MqttError("short PUBLISH topic")
        topic = body[2:2 + topic_len].decode()
        offset = 2 + topic_len
        qos = (header >> 1) & 0x03
        if qos:
            if len(body) < offset + 2:
                raise MqttError("short PUBLISH packet id")
            packet_id = body[offset:offset + 2]
            offset += 2
            if qos == 1:
                self._send(0x40, packet_id)
        return topic, body[offset:], bool(header & 0x01)

    def subscribe(self, topic: str, *, qos: int = 0) -> int:
        packet_id = self._next_packet_id()
        self._send(0x82, struct.pack("!H", packet_id) + _utf8(topic) + bytes((qos,)))
        while True:
            header, body = self._recv_packet()
            packet_type = header >> 4
            if packet_type == 3:
                self._queued.append(self._decode_publish(header, body))
                continue
            if packet_type == 9 and len(body) >= 3:
                received = struct.unpack("!H", body[:2])[0]
                if received == packet_id:
                    return body[2]

    def receive(self, *, timeout: float | None = None) -> tuple[str, bytes, bool]:
        if self._queued:
            return self._queued.pop(0)
        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            while True:
                header, body = self._recv_packet()
                if header >> 4 == 3:
                    return self._decode_publish(header, body)
        finally:
            self.sock.settimeout(old_timeout)

    def publish(self, topic: str, payload: bytes | str, *, qos: int = 1,
                retain: bool = True) -> None:
        raw = payload.encode() if isinstance(payload, str) else payload
        packet_id = self._next_packet_id()
        body = _utf8(topic)
        if qos:
            body += struct.pack("!H", packet_id)
        body += raw
        self._send(0x30 | (qos << 1) | int(retain), body)
        if qos != 1:
            return
        while True:
            header, response = self._recv_packet()
            if header >> 4 == 3:
                self._queued.append(self._decode_publish(header, response))
                continue
            if header >> 4 == 4 and response == struct.pack("!H", packet_id):
                return

    def close(self) -> None:
        sock = getattr(self, "sock", None)
        if sock is None:
            return
        try:
            self._send(0xE0, b"")
        except OSError:
            pass
        try:
            sock.close()
        finally:
            self.sock = None

    def __enter__(self) -> "MqttClient":
        return self

    def __exit__(self, *_args) -> None:
        self.close()
