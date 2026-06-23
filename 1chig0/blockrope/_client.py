"""Raw-socket protocol client for blockrope (nclib line/menu protocol on TCP 1337).

The service is `python3 main.py` run per-connection behind an inetd wrapper.
It speaks a line-based menu over the socket and interleaves terminal-clear
escape codes (it calls `os.system("clear")`), so every step keys off a stable
text marker via `recv_until` rather than parsing whole screens.

Account-bearing flows used by the flag handler / functionality test:
    register_random -> creates an account, returns its numeric id
    send_money      -> transfers funds with a transaction message (flag carrier)
    login           -> authenticates an existing account
    history         -> dumps recent transactions (where the flag is read back)
    logout          -> returns to the start screen
"""
from __future__ import annotations

import logging
import re

import nclib

log = logging.getLogger(__name__)

PORT = 1337
_TIMEOUT = 5
_PROMPT = b"> "


class ClientError(Exception):
    """Protocol-level failure (unexpected response / missing marker)."""


def connect(ip):
    try:
        conn = nclib.Netcat((ip, PORT), raise_timeout=True)
        conn.settimeout(_TIMEOUT)
        return conn
    except nclib.NetcatError:
        return None


def _wait_menu(conn) -> None:
    """Consume output up to the next start-screen / main-screen `> ` prompt."""
    conn.recv_until(_PROMPT)


def register_random(conn, password: str, recovery: str) -> str:
    """Register a fresh account with a server-generated id; return that id.

    Must be called from the start screen (just-connected, or right after a
    logout). Leaves the connection inside the new account's main screen.
    """
    _wait_menu(conn)
    conn.sendline(b"register")
    conn.recv_until(b"User ID:")
    conn.sendline(b"random")
    data = conn.recv_until(b"Password:")
    m = re.search(rb"User ID:\s*(\d+)", data)
    if m is None:
        raise ClientError("no auto-generated user id in register response")
    uid = m.group(1).decode("ascii")
    conn.sendline(password.encode("latin-1"))
    conn.recv_until(b"Repeat password:")
    conn.sendline(password.encode("latin-1"))
    conn.recv_until(b"Recovery phrase:")
    conn.sendline(recovery.encode("latin-1"))
    data = conn.recv_until(_PROMPT)
    if b"Welcome user" not in data:
        raise ClientError("registration did not reach the account main screen")
    return uid


def send_money(conn, receiver_id: str, amount: float, message: str) -> None:
    """Send `amount` to `receiver_id` with `message` (the flag carrier).

    Must be called from a logged-in main screen.
    """
    conn.sendline(b"send")
    conn.recv_until(b"Receiver:")
    conn.sendline(receiver_id.encode("latin-1"))
    conn.recv_until(b"amount:")
    conn.sendline(f"{amount:0.2f}".encode("latin-1"))
    conn.recv_until(b"message")
    conn.sendline(message.encode("latin-1"))
    data = conn.recv_until(b"Transaction successfully send!")
    if b"Insufficient balance" in data:
        raise ClientError("insufficient balance to send")


def logout(conn) -> None:
    conn.sendline(b"logout")
    _wait_menu(conn)


def login(conn, uid: str, password: str) -> None:
    """Authenticate an existing account from the start screen.

    Leaves the connection inside that account's main screen.
    """
    _wait_menu(conn)
    conn.sendline(b"login")
    conn.recv_until(b"User ID:")
    conn.sendline(uid.encode("latin-1"))
    conn.recv_until(b"password:")
    conn.sendline(password.encode("latin-1"))
    data = conn.recv_until(_PROMPT)
    if b"Welcome user" not in data:
        raise ClientError("login failed (wrong credentials or missing account)")


def history(conn) -> str:
    """Return the rendered transaction history for the logged-in account."""
    conn.sendline(b"history")
    data = conn.recv_until(b"<Press Enter to continue>")
    conn.sendline(b"")
    _wait_menu(conn)
    return data.decode("latin-1", errors="replace")
