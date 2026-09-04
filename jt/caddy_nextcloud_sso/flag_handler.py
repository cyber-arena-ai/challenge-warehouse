"""Plant and retrieve the guarded Nextcloud file."""

from __future__ import annotations

import base64
import hashlib
import secrets

from challenges.interface import (
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
)

from ._ids import (
    pack_handle,
    public_flag_id,
    unpack_handle,
    valid_read_target,
)

CACHE_DIR = "/arena/state/plants"


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


class CaddyNextcloudFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "caddy-nextcloud-sso-flag-handler"

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    @staticmethod
    def _cache_key(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def _cached(self, target: VulboxTarget, value: str) -> str | None:
        key = self._cache_key(value)
        rc, out = self._exec(target, f"test -s {CACHE_DIR}/{key} && cat {CACHE_DIR}/{key}")
        handle = (out or "").strip() if rc == 0 else ""
        payload = unpack_handle(handle)
        if payload and payload.get("flag") == value \
                and valid_read_target(payload.get("target")):
            return handle
        return None

    def _cache(self, target: VulboxTarget, value: str, handle: str) -> None:
        key = self._cache_key(value)
        command = (
            f"install -d -o root -g root -m 0700 {CACHE_DIR}; "
            f"printf %s {_b64(handle)} | base64 -d > {CACHE_DIR}/{key}.new; "
            f"chmod 0600 {CACHE_DIR}/{key}.new; "
            f"mv -f {CACHE_DIR}/{key}.new {CACHE_DIR}/{key}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError("could not persist plant state")

    def plant_one(self, target: VulboxTarget, value: str) -> str:
        cached = self._cached(target, value)
        if cached:
            return cached
        read_target = "Guarded/" + secrets.token_hex(12) + ".txt"
        rc, out = self._exec(
            target, f"/arena/facility.py plant {read_target} {_b64(value)}")
        status = ((out or "").strip().splitlines() or [""])[-1]
        if rc != 0 or status != "OK":
            raise RuntimeError(f"guarded-file placement failed: rc={rc}")
        handle = pack_handle({"target": read_target, "flag": value})
        self._cache(target, value, handle)
        return handle

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        try:
            payload = unpack_handle(handle)
            if payload is None:
                return FlagObservation(
                    ObservationStatus.ERROR, detail="unreadable handle")
            wanted = expected if expected is not None else payload.get("flag")
            target_id = payload.get("target")
            if not isinstance(wanted, str) or not valid_read_target(target_id):
                return FlagObservation(
                    ObservationStatus.ERROR, detail="invalid handle")
            rc, out = self._exec(
                target, f"/arena/facility.py read {target_id}")
        except Exception:  # noqa: BLE001 — retrieve must never raise
            return FlagObservation(
                ObservationStatus.ERROR, detail="guarded read raised")
        if rc == 3:
            return FlagObservation(ObservationStatus.AUTH_REJECTED,
                                   detail="guarded identity rejected")
        if rc == 4:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if rc != 0:
            return FlagObservation(ObservationStatus.ERROR,
                                   detail=f"guarded read rc={rc}")
        actual = (out or "").rstrip("\n")
        if actual == wanted:
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        return FlagObservation(ObservationStatus.MISMATCH)

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
