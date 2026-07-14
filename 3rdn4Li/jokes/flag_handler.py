"""FlagHandler for faust-jokes.

Inlines the upstream checker's `place_flag` / `check_flag`. The flag is
planted as a hidden draft joke via an RSA-signed `submit_draft(flag_id, flag)`
admin command, then made visible to `query_jokes(True)`. Reuses the vendored
RSA `private.key` (`_checker/private.key`) unmodified.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import uuid

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from challenges.interface import SingleFlagHandler, VulboxTarget

from . import _net

log = logging.getLogger(__name__)

_TIMEOUT = 10
_TEAM = 0  # must match the vulbox's /etc/team-num (entrypoint bakes 0: one team per vulbox)
_KEY_PATH = os.path.join(os.path.dirname(__file__), "_checker", "private.key")


def _sign(message: str) -> bytes:
    with open(_KEY_PATH, "rb") as key_file:
        key = RSA.importKey(key_file.read())
    return pkcs1_15.new(key).sign(SHA256.new(message.encode()))


def _signed_payload(action: str) -> dict:
    msg = json.dumps({"action": action, "team": _TEAM})
    return {"message": msg, "hash": _sign(msg).hex()}


def _authed_session(base: str) -> requests.Session | None:
    """Register a fresh account + login -> an authenticated Session, or None."""
    creds = {"name": str(uuid.uuid4()), "password": secrets.token_hex(16)}
    r = requests.post(base + "/register", data=creds, timeout=_TIMEOUT)
    if r.status_code != 200:
        return None
    s = requests.Session()
    r = s.post(base + "/login", data=creds, timeout=_TIMEOUT)
    if r.status_code != 200:
        s.close()
        return None
    return s


class JokesFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "faust-jokes-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        base = _net.base_url(target)
        s = _authed_session(base)
        if s is None:
            raise RuntimeError(f"{self.name}: register/login failed")
        try:
            flag_id = secrets.token_hex(8)
            r = s.post(base + "/profile",
                       data=_signed_payload(f'rv = submit_draft("{flag_id}", "{flag}")'),
                       timeout=_TIMEOUT)
            if r.status_code != 200:
                raise RuntimeError(f"{self.name}: submit_draft failed {r.status_code}")
            r = s.post(base + "/profile",
                       data=_signed_payload("rv = process_reviewed_jokes()"),
                       timeout=_TIMEOUT)
            if r.status_code != 200:
                raise RuntimeError(f"{self.name}: process_reviewed_jokes failed {r.status_code}")
        finally:
            s.close()
        return base64.b64encode(json.dumps(
            {"flagid": flag_id, "flag": flag}).encode()).decode("ascii")

    def retrieve(self, target: VulboxTarget, handle: str) -> str | None:
        try:
            st = json.loads(base64.b64decode(handle))
            flag = st["flag"]
        except Exception:
            return None
        base = _net.base_url(target)
        s = _authed_session(base)
        if s is None:
            return None
        try:
            r = s.post(base + "/profile",
                       data=_signed_payload("rv = query_jokes(True)"), timeout=_TIMEOUT)
        except Exception:
            return None
        finally:
            s.close()
        if r.status_code != 200:
            return None
        return flag if flag in r.text else None
