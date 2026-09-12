"""Minimal TLS/SASL XMPP workflow used by the external checker."""

from __future__ import annotations

import base64
import socket
import ssl
import time


DOMAIN = "openfire.test"


def _receive_until(sock: socket.socket, marker: bytes, timeout: float = 20.0) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("XMPP connection closed early")
        data.extend(chunk)
    return bytes(data)


def _stream_header(sock: socket.socket) -> bytes:
    sock.sendall(
        (
            f"<stream:stream to='{DOMAIN}' xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        ).encode()
    )
    return _receive_until(sock, b"</stream:features>")


def _connect(host: str, port: int, username: str, password: str, resource: str):
    raw = socket.create_connection((host, port), timeout=20)
    if b"urn:ietf:params:xml:ns:xmpp-tls" not in _stream_header(raw):
        raise RuntimeError("XMPP TLS feature unavailable")
    raw.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    _receive_until(raw, b"<proceed")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    wrapped = context.wrap_socket(raw, server_hostname=DOMAIN)
    if b">PLAIN<" not in _stream_header(wrapped):
        raise RuntimeError("XMPP SASL PLAIN unavailable")
    payload = base64.b64encode(f"\0{username}\0{password}".encode()).decode()
    wrapped.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{payload}</auth>".encode()
    )
    _receive_until(wrapped, b"<success")
    if b"urn:ietf:params:xml:ns:xmpp-bind" not in _stream_header(wrapped):
        raise RuntimeError("XMPP resource binding unavailable")
    wrapped.sendall(
        (
            "<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
            f"<resource>{resource}</resource></bind></iq>"
        ).encode()
    )
    bound = _receive_until(wrapped, b"</iq>")
    if f"{username}@{DOMAIN}/{resource}".encode() not in bound:
        raise RuntimeError("XMPP resource binding failed")
    wrapped.sendall(b"<presence/>")
    return wrapped


def exchange(
    host: str,
    port: int,
    sender: tuple[str, str],
    receiver: tuple[str, str],
    marker: str,
) -> None:
    receiving = _connect(host, port, receiver[0], receiver[1], "receiver")
    sending = _connect(host, port, sender[0], sender[1], "sender")
    try:
        time.sleep(0.25)
        sending.sendall(
            (
                f"<message to='{receiver[0]}@{DOMAIN}' type='chat'>"
                f"<body>{marker}</body></message>"
            ).encode()
        )
        if marker.encode() not in _receive_until(receiving, marker.encode()):
            raise RuntimeError("XMPP message was not delivered")
    finally:
        for client in (sending, receiving):
            try:
                client.sendall(b"</stream:stream>")
                client.close()
            except OSError:
                pass
