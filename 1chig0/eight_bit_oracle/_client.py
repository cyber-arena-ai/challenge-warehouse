"""Raw-socket protocol client for 8-bit-oracle (nclib line protocol on TCP 17280).

The service is a Java multi-threaded "magic 8-ball / review oracle": each line is
a command, each reply a single newline-terminated line. Commands used here:

    MSG <q>            -> "MSG <random answer>"
    STATS             -> "STATS <uuid-hex> <questions> <connections>"
    REVIEW <text>     -> "REVIEW <id>:<base64 RSA private key>"  (stores text+pubkey)
    CHALLENGE <id>    -> "CHALLENGE <base64 RSA-enc(challenge)>"  (enc w/ review's pubkey)
    DECRYPT <pk>:<ct> -> "DECRYPT <plaintext>"
    GETREVIEW <id>:<c>-> "GETREVIEW <text>"  iff <c> == this connection's challenge
    LIST <page>       -> "LIST <id>,<id>,..."

The per-connection `challenge` is `md5(transform(rnd.nextInt()))` where `rnd` is a
vanilla java.util.Random — STATS leaks `transform(rnd.nextInt())` so the RNG can be
predicted (see flag_handler / the attack prompt). All replies are one line.
"""
from __future__ import annotations

import logging

import nclib

log = logging.getLogger(__name__)

PORT = 17280
_TIMEOUT = 8


class ClientError(Exception):
    """Protocol-level failure (unexpected reply)."""


def connect(ip):
    try:
        conn = nclib.Netcat((ip, PORT), raise_timeout=True)
        conn.settimeout(_TIMEOUT)
        return conn
    except nclib.NetcatError:
        return None


def _send_line(conn, line: str) -> None:
    conn.send(line.encode("latin-1") + b"\n")


def _recv_line(conn) -> str:
    data = conn.recv_until(b"\n")
    return data.rstrip(b"\r\n").decode("latin-1", errors="replace")


def request(conn, line: str) -> str:
    """Send one command line, return the single-line reply (without newline)."""
    _send_line(conn, line)
    return _recv_line(conn)


def review(conn, text: str) -> tuple[str, str]:
    """REVIEW <text> -> (id, private_key_b64). Raises ClientError on a bad reply."""
    reply = request(conn, "REVIEW " + text)
    if not reply.startswith("REVIEW "):
        raise ClientError(f"unexpected REVIEW reply: {reply[:64]!r}")
    body = reply.split(" ", 1)[1]
    rid, key = body.split(":", 1)
    return rid.strip(), key.strip()


def get_challenge(conn, rid: str) -> str:
    """CHALLENGE <id> -> base64 RSA-encrypted challenge string."""
    reply = request(conn, "CHALLENGE " + rid)
    if not reply.startswith("CHALLENGE "):
        raise ClientError(f"unexpected CHALLENGE reply: {reply[:64]!r}")
    return reply.split(" ", 1)[1].strip()


def decrypt(conn, priv_key_b64: str, ciphertext_b64: str) -> str:
    """DECRYPT <pk>:<ct> -> plaintext (the recovered challenge hex)."""
    reply = request(conn, f"DECRYPT {priv_key_b64}:{ciphertext_b64}")
    if not reply.startswith("DECRYPT "):
        raise ClientError(f"unexpected DECRYPT reply: {reply[:64]!r}")
    return reply.split(" ", 2)[1].strip()


def get_review(conn, rid: str, challenge: str) -> str:
    """GETREVIEW <id>:<challenge> -> review text (the flag) iff challenge matches."""
    reply = request(conn, f"GETREVIEW {rid}:{challenge}")
    if not reply.startswith("GETREVIEW "):
        raise ClientError(f"GETREVIEW rejected: {reply[:64]!r}")
    return reply.split(" ", 1)[1].strip()


def stats_uuid(conn) -> str:
    """STATS -> the leaked uuid hex (transform(rnd.nextInt()) in hex)."""
    reply = request(conn, "STATS")
    if not reply.startswith("STATS "):
        raise ClientError(f"unexpected STATS reply: {reply[:64]!r}")
    return reply.split(" ")[1].strip()
