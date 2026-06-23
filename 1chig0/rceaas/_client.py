"""Raw-socket protocol client for rceaas (nclib line protocol on TCP 1835).

The service is the Rust "RCE as a Service" jail run per-connection behind an
inetd wrapper: a login (username + password) followed by a `C:/>`-style shell.
Over a raw socket (no PTY) rustyline neither echoes input nor prints the prompt,
and command output has no terminator. So login keys off the static banner, and
each command is delimited by chasing it with `echo <random-marker>` and reading
up to that marker — the output in between is the command's result.
"""
from __future__ import annotations

import logging
import secrets

import nclib

log = logging.getLogger(__name__)

PORT = 1835
_TIMEOUT = 6


class ClientError(Exception):
    """Protocol-level failure (unexpected banner / login rejected)."""


def connect(ip):
    try:
        conn = nclib.Netcat((ip, PORT), raise_timeout=True)
        conn.settimeout(_TIMEOUT)
        return conn
    except nclib.NetcatError:
        return None


def login(conn, username: str, password: str) -> None:
    """Authenticate (creating the account on first use). Leaves the connection
    at the shell. Raises ClientError if the banner/login is wrong."""
    data = conn.recv_until(b":")            # "Enter your username:"
    if b"Enter your username" not in data:
        raise ClientError("missing username banner")
    conn.sendline(username.encode("latin-1"))
    data = conn.recv_until(b":")            # "Enter your password:"
    if b"Enter your password" not in data:
        raise ClientError("missing password banner")
    conn.sendline(password.encode("latin-1"))
    data = conn.recv_until(b"\n")          # banner line (or "Wrong password!")
    if b"RCE as a Service" not in data:
        raise ClientError("login rejected (wrong password?)")


def cmd(conn, command: str) -> str:
    """Run one shell command; return its output (delimited by a sentinel echo)."""
    marker = "Z" + secrets.token_hex(8) + "Z"
    conn.sendline(command.encode("latin-1"))
    conn.sendline(b"echo " + marker.encode("ascii"))
    data = conn.recv_until(marker.encode("ascii"))
    return data[: -len(marker)].decode("latin-1", errors="replace")
