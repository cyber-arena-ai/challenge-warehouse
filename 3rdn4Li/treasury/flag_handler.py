"""FlagHandler for faust-treasury.

Inlines the upstream `place_flag` / `check_flag`: add a treasure entry under a
freshly generated 60-char key with the flag as its description; retrieve views
that key and reads the flag back. The key (the upstream's gameserver-state
flag->key map) is carried in the handle. pwn protocol helpers in `_client.py`.
"""
from __future__ import annotations

import base64
import json
import logging

from challenges.interface import (
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
)

from . import _client, _net

log = logging.getLogger(__name__)


def _pack(state: dict) -> str:
    return base64.b64encode(json.dumps(state).encode()).decode("ascii")


def _unpack(handle: str) -> dict | None:
    try:
        st = json.loads(base64.b64decode(handle))
        return st if isinstance(st, dict) and "flag" in st else None
    except Exception:
        return None


class TreasuryFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "faust-treasury-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        ip = _net.resolve(target)
        key = _client.generate_random_string(60)
        try:
            ret = _client.add_treasure(ip, key, flag)
            while ret == 2:  # key collision — regenerate and retry
                key = _client.generate_random_string(60)
                ret = _client.add_treasure(ip, key, flag)
        except ConnectionRefusedError as e:
            raise RuntimeError(f"{self.name}: connect failed (DOWN): {e}") from e
        if ret != 0:
            raise RuntimeError(f"{self.name}: add_treasure returned {ret}")
        # The location key is facility-private state.  Supplying it as public
        # attack-info would let an attacker use the ordinary ``view`` command
        # to read the flag without exercising the log-dispatch vulnerability.
        return _pack({"key": key, "flag": flag})

    def retrieve(self, target: VulboxTarget, handle: str, expected: str | None = None) -> FlagObservation:
        """Structured, read-only observation via the view_treasure path."""
        try:
            st = _unpack(handle)
            if st is None:
                return FlagObservation(ObservationStatus.ERROR, detail="bad handle")
            exp = expected if expected is not None else st["flag"]
            try:
                val = _client.view_treasure(_net.resolve(target), st["key"])
            except ConnectionRefusedError:
                return FlagObservation(ObservationStatus.ERROR, detail="connect refused (DOWN)")
            if not val:
                return FlagObservation(ObservationStatus.NOT_FOUND, detail="treasure gone")
            try:
                decoded = val.decode()
            except UnicodeDecodeError:
                return FlagObservation(ObservationStatus.ERROR, detail="undecodable treasure")
            if decoded == exp:
                return FlagObservation(ObservationStatus.PRESENT, value=decoded)
            return FlagObservation(ObservationStatus.MISMATCH, value=decoded)
        except Exception as e:  # noqa: BLE001 — retrieve must never raise
            return FlagObservation(ObservationStatus.ERROR, detail=f"unexpected: {type(e).__name__}")
