"""FlagHandler for blockrope.

Mirrors the upstream saarCTF checker's store/retrieve: register a receiver and
a sender account, then have the sender transfer funds to the receiver with the
flag as the transaction message. The flag is read back by logging in as the
receiver and dumping the transaction history. Raw line-protocol helpers live in
`_client.py`.
"""
from __future__ import annotations

import base64
import json
import logging
import secrets
import string

import nclib

from challenges.interface import FlagHandler, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)

_ALNUM = string.ascii_letters + string.digits


def _cred(n: int = 12) -> str:
    return "".join(secrets.choice(_ALNUM) for _ in range(n))


def _pack(state: dict) -> str:
    return base64.b64encode(json.dumps(state).encode()).decode("ascii")


def _unpack(handle: str) -> dict | None:
    try:
        st = json.loads(base64.b64decode(handle))
        return st if isinstance(st, dict) and "flag" in st else None
    except Exception:
        return None


class BlockRopeFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "blockrope-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant(self, target: VulboxTarget, flag: str) -> str:
        conn = _client.connect(_net.resolve(target))
        if conn is None:
            raise RuntimeError(f"{self.name}: connect failed (DOWN)")
        try:
            receiver_pw = _cred()
            receiver_id = _client.register_random(conn, receiver_pw, _cred(10))
            _client.logout(conn)

            sender_pw = _cred()
            _client.register_random(conn, sender_pw, _cred(10))
            _client.send_money(conn, receiver_id, 1.00, flag)
        except (_client.ClientError, nclib.NetcatError, UnicodeError) as e:
            raise RuntimeError(f"{self.name}: plant failed: {e}") from e
        finally:
            conn.close()
        return _pack({
            "flagid": receiver_id,
            "receiver_id": receiver_id,
            "receiver_pw": receiver_pw,
            "flag": flag,
        })

    def retrieve(self, target: VulboxTarget, handle: str) -> str | None:
        st = _unpack(handle)
        if st is None:
            return None
        conn = _client.connect(_net.resolve(target))
        if conn is None:
            return None
        try:
            _client.login(conn, st["receiver_id"], st["receiver_pw"])
            data = _client.history(conn)
            return st["flag"] if st["flag"] in data else None
        except (_client.ClientError, nclib.NetcatError, UnicodeError):
            return None
        finally:
            conn.close()
