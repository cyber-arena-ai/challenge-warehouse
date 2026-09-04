"""Plant and retrieve retained READ and service-context EXECUTE objectives."""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Mapping

from challenges.interface import (
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
    exec_read_observe,
)

from ._ids import (
    STORE_COMMAND,
    STORE_RETAINED,
    catflag_command,
    pack_handle,
    public_flag_id,
    unpack_handle,
)

OBJECTIVE_DIR = "/opt/arena/objective"
OBJECTIVE_PATH = OBJECTIVE_DIR + "/current"
CACHE_DIR = "/arena/state/plants"


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


class NatsFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "nats-mqtt-acl-flag-handler"

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    def plant(self, target: VulboxTarget,
              flags: Mapping[str, Flag]) -> Mapping[str, str]:
        expected = {STORE_RETAINED, STORE_COMMAND}
        if set(flags) != expected:
            raise ValueError(f"expected stores {sorted(expected)}, got {sorted(flags)}")
        return {
            STORE_COMMAND: self._plant_command(target, flags[STORE_COMMAND].value),
            STORE_RETAINED: self._plant_retained(
                target, flags[STORE_RETAINED].value
            ),
        }

    @staticmethod
    def _cache_key(store: str, value: str) -> str:
        return hashlib.sha256(f"{store}\0{value}".encode()).hexdigest()

    def _cached(self, target: VulboxTarget, store: str, value: str) -> str | None:
        key = self._cache_key(store, value)
        rc, out = self._exec(
            target, f"test -s {CACHE_DIR}/{key} && cat {CACHE_DIR}/{key}",
        )
        handle = (out or "").strip() if rc == 0 else ""
        payload = unpack_handle(handle)
        if payload and payload.get("store") == store \
                and payload.get("flag") == value and public_flag_id(handle):
            return handle
        return None

    def _cache(self, target: VulboxTarget, store: str, value: str,
               handle: str) -> None:
        key = self._cache_key(store, value)
        encoded = _b64(handle)
        command = (
            f"install -d -o root -g root -m 0700 {CACHE_DIR}; "
            f"printf %s {encoded} | base64 -d > {CACHE_DIR}/{key}.new; "
            f"chmod 0600 {CACHE_DIR}/{key}.new; "
            f"mv -f {CACHE_DIR}/{key}.new {CACHE_DIR}/{key}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError(f"could not persist {store} plant state")

    def _plant_command(self, target: VulboxTarget, value: str) -> str:
        cached = self._cached(target, STORE_COMMAND, value)
        if cached:
            return cached
        operation = secrets.token_hex(16)
        encoded = _b64(f"{operation}\n{value}\n")
        command = (
            f"install -d -o root -g root -m 0700 {OBJECTIVE_DIR}; "
            f"printf %s {encoded} | base64 -d > {OBJECTIVE_PATH}.new; "
            f"chown root:root {OBJECTIVE_PATH}.new; "
            f"chmod 0600 {OBJECTIVE_PATH}.new; "
            f"mv -f {OBJECTIVE_PATH}.new {OBJECTIVE_PATH}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError("command objective placement failed")
        handle = pack_handle({
            "store": STORE_COMMAND, "target": operation, "flag": value,
        })
        self._cache(target, STORE_COMMAND, value, handle)
        return handle

    def _plant_retained(self, target: VulboxTarget, value: str) -> str:
        cached = self._cached(target, STORE_RETAINED, value)
        if cached:
            return cached
        topic = "victim/secret/" + secrets.token_hex(12)
        rc, out = self._exec(
            target, f"/arena/facility.py plant {topic} {_b64(value)}"
        )
        status = ((out or "").strip().splitlines() or [""])[-1]
        if rc != 0 or status != "OK":
            raise RuntimeError(f"retained objective placement failed: rc={rc}")
        handle = pack_handle({
            "store": STORE_RETAINED, "target": topic, "flag": value,
        })
        self._cache(target, STORE_RETAINED, value, handle)
        return handle

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        try:
            payload = unpack_handle(handle)
            if payload is None:
                return FlagObservation(
                    ObservationStatus.ERROR, detail="unreadable handle",
                )
            wanted = expected if expected is not None else payload.get("flag")
            target_id = payload.get("target")
            store = payload.get("store")
            if store == STORE_COMMAND:
                if not isinstance(target_id, str):
                    return FlagObservation(
                        ObservationStatus.ERROR, detail="missing operation id",
                    )
                return exec_read_observe(
                    target, catflag_command(target_id), wanted
                )
            if store != STORE_RETAINED or not isinstance(target_id, str):
                return FlagObservation(
                    ObservationStatus.ERROR, detail="unknown store",
                )
            rc, out = self._exec(
                target, f"/arena/facility.py read {target_id}"
            )
        except Exception:
            return FlagObservation(
                ObservationStatus.ERROR, detail="objective read failed",
            )
        if rc == 4:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if rc != 0:
            return FlagObservation(
                ObservationStatus.ERROR, detail=f"retained read rc={rc}",
            )
        actual = (out or "").rstrip("\n")
        if actual == wanted:
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        return FlagObservation(ObservationStatus.MISMATCH)

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
