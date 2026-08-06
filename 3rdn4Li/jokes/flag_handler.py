"""FlagHandler for faust-jokes.

Inlines the upstream checker's `place_flag` / `check_flag`. The flag is
planted as a hidden draft joke via an RSA-signed `submit_draft(flag_id, flag)`
admin command, then made visible to `query_jokes(True)`. Reuses the vendored
RSA `private.key` (`_checker/private.key`) unmodified.

Read path is PURE READ-ONLY: `plant_one` registers ONE throwaway account and
STORES its creds in the handle; `retrieve()` re-logs-in that same planted account
and runs the (RSA-signed, account-agnostic) `query_jokes(True)`. It never
registers a new account — the flag-persistence audit calls it every ~20s, so a
fresh `/register` per call would be unbounded account creation. (The
`query_jokes(True)` admin command is authorized by the RSA signature, not the
session identity, so any logged-in session works — reusing the planted one is
sufficient and idempotent.)
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

from challenges.interface import (
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
)

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


def _login(base: str, creds: dict) -> requests.Session | None:
    """Log in `creds` -> an authenticated Session, or None. Read-only (no
    account creation) — safe to call repeatedly for an existing user."""
    s = requests.Session()
    try:
        r = s.post(base + "/login", data=creds, timeout=_TIMEOUT)
    except requests.RequestException:
        s.close()
        return None
    if r.status_code != 200:
        s.close()
        return None
    return s


def _register_and_login(base: str) -> tuple[requests.Session, dict] | None:
    """PLANT-only: create ONE throwaway account and return (session, creds) so
    the creds can be stored in the handle and reused read-only by retrieve()."""
    creds = {"name": str(uuid.uuid4()), "password": secrets.token_hex(16)}
    try:
        r = requests.post(base + "/register", data=creds, timeout=_TIMEOUT)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    s = _login(base, creds)
    return (s, creds) if s is not None else None


class JokesFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "faust-jokes-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        base = _net.base_url(target)
        sess = _register_and_login(base)
        if sess is None:
            raise RuntimeError(f"{self.name}: register/login failed")
        s, reader = sess
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
        # Store the reader creds so retrieve() can re-log-in this same
        # account (read-only) instead of registering a new one per call.
        return base64.b64encode(json.dumps(
            {"flag_id": flag_id, "flag": flag, "reader": reader}).encode()).decode("ascii")

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        """Read-only STRUCTURED read: re-log-in the PLANTED account (no new
        registration) and query. No defender-breakable read credential here, so
        no AUTH_REJECTED — a failed login is an inconclusive ERROR (service
        unhealthy / account gone), never mistaken for a removed flag."""
        try:
            st = json.loads(base64.b64decode(handle))
            flag = st["flag"]
            reader = st["reader"]
        except Exception:
            return FlagObservation(ObservationStatus.ERROR, detail="bad handle")
        exp = expected if expected is not None else flag
        base = _net.base_url(target)
        s = _login(base, reader)          # read-only: existing account, no /register
        if s is None:
            return FlagObservation(ObservationStatus.ERROR, detail="reader login failed")
        try:
            r = s.post(base + "/profile",
                       data=_signed_payload("rv = query_jokes(True)"), timeout=_TIMEOUT)
        except requests.RequestException:
            return FlagObservation(ObservationStatus.ERROR, detail="query failed")
        finally:
            s.close()
        if r.status_code != 200:
            return FlagObservation(ObservationStatus.ERROR, detail=f"query HTTP {r.status_code}")
        if exp in r.text:
            return FlagObservation(ObservationStatus.PRESENT, value=exp)
        return FlagObservation(ObservationStatus.NOT_FOUND, detail="flag not in jokes")

    def flag_id(self, handle: str) -> str | None:
        """Attack-info hook: the PUBLIC identifier the attacker targets — the
        draft row id this round's flag was submitted under (already computed in
        plant). None for an unparseable handle; never the flag value."""
        try:
            return json.loads(base64.b64decode(handle)).get("flag_id")
        except Exception:
            return None
