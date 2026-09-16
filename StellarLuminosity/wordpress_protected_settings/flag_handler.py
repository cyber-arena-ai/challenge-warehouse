"""Application-native placement for one protected WordPress setting."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import json
import shlex

from challenges.interface import (
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
)

from ._codec import (
    STORE,
    context_id,
    pack_handle,
    target_option,
    unpack_handle,
    valid_target,
)


def _encoded(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.b64encode(raw).decode()


class WordPressFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "wordpress-protected-setting-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _invoke(target: VulboxTarget, operation: str, value: object) -> tuple[int, str]:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            raise RuntimeError("facility application bridge is unavailable")
        return exec_in(
            target.host,
            f"/arena/facility.py {shlex.quote(operation)} {_encoded(value)}",
        )

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected store {STORE!r}, got {sorted(flags)}")
        seed = target.meta.get("round_context_seed")
        if not isinstance(seed, str):
            raise ValueError("round_context_seed is required")
        target_id = target_option(seed)
        proof = flags[STORE].value
        request = {
            "context": context_id(seed),
            "target": target_id,
            "value": proof,
        }
        rc, output = self._invoke(target, "plant", request)
        if rc != 0 or (output or "").strip() != "OK":
            raise RuntimeError(f"protected-setting placement failed (rc={rc})")
        return {STORE: pack_handle(target_id, proof)}

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        state = unpack_handle(handle)
        if state is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        target_id, planted = state
        try:
            rc, output = self._invoke(target, "read", {"target": target_id})
            if rc == 4:
                return FlagObservation(ObservationStatus.NOT_FOUND)
            if rc != 0:
                return FlagObservation(
                    ObservationStatus.ERROR,
                    detail=f"protected setting read rc={rc}",
                )
            actual = (output or "").rstrip("\n")
            if not actual:
                return FlagObservation(ObservationStatus.NOT_FOUND)
            wanted = expected if expected is not None else planted
            if actual != wanted:
                return FlagObservation(ObservationStatus.MISMATCH, value=actual)
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        except Exception as error:  # noqa: BLE001 — observation must not raise
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=f"protected setting read failed: {type(error).__name__}",
            )

    def flag_id(self, handle: str) -> str | None:
        state = unpack_handle(handle)
        if state is None:
            return None
        target, _ = state
        return target if valid_target(target) else None
