"""Minimal TLS/SASL XMPP workflow used by the external checker."""

from __future__ import annotations

import base64
import secrets
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
    roster: list[tuple[str, str]],
    markers: list[str],
) -> None:
    """Authenticate fresh as every roster identity and rotate one message each.

    Each identity sends to the next and receives from the previous, so no member
    of the roster is reachable without its own password. Every message is
    addressed to the receiver's FULL JID: a bare JID routes to whichever session
    of that account was most recently active, and these accounts are also held
    by their participants, so bare addressing would let any participant keeping
    a livelier session collect this probe's traffic instead.
    """
    resources = [
        f"{('desktop', 'mobile')[index % 2]}-{secrets.randbelow(900) + 100}"
        for index in range(len(roster))
    ]
    clients = []
    try:
        for (username, password), resource in zip(roster, resources):
            clients.append(_connect(host, port, username, password, resource))
        time.sleep(0.25)
        for index, client in enumerate(clients):
            receiver = (index + 1) % len(roster)
            client.sendall(
                (
                    f"<message to='{roster[receiver][0]}@{DOMAIN}/{resources[receiver]}'"
                    f" type='chat'><body>{markers[index]}</body></message>"
                ).encode()
            )
        for index, client in enumerate(clients):
            try:
                _receive_until(client, markers[index - 1].encode())
            except (OSError, RuntimeError) as error:
                raise RuntimeError("XMPP message was not delivered") from error
    finally:
        for client in clients:
            try:
                client.sendall(b"</stream:stream>")
                client.close()
            except OSError:
                pass
