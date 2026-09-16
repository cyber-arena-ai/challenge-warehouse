"""Convergent placement and observation of one execution witness."""

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

from ._ids import STORE, pack_handle, public_locator, round_context, unpack_handle


def _encoded(value: object) -> str:
    return base64.b64encode(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).decode()


class GogsExecutionFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "gogs-code-collaboration-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _invoke(
        target: VulboxTarget, operation: str, payload: object
    ) -> tuple[int, str]:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            raise RuntimeError("facility application bridge is unavailable")
        encoded = _encoded(payload)
        command = (
            f"printf %s {shlex.quote(encoded)} | "
            f"/arena/facility.py {shlex.quote(operation)}"
        )
        return exec_in(target.host, command)

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected exactly {STORE!r}")
        seed = target.meta.get("round_context_seed")
        if not isinstance(seed, str):
            raise ValueError("round_context_seed is required")
        identity = round_context(seed)
        request = {
            **identity,
            "store": STORE,
            "token": flags[STORE].value,
        }
        rc, output = self._invoke(target, "plant", request)
        if rc != 0 or (output or "").strip() != "OK":
            detail = (output or "").strip().splitlines()[-1:] or ["no detail"]
            raise RuntimeError(
                f"execution witness placement failed (rc={rc}): {detail[0][:240]}"
            )
        return {STORE: pack_handle(request)}

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        state = unpack_handle(handle)
        if state is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        try:
            rc, output = self._invoke(
                target, "observe", {"operation": state["operation"]}
            )
            if rc == 4:
                return FlagObservation(ObservationStatus.NOT_FOUND)
            if rc != 0:
                return FlagObservation(
                    ObservationStatus.ERROR,
                    detail=f"execution witness returned rc={rc}",
                )
            actual = (output or "").rstrip("\n")
            wanted = expected if expected is not None else state["token"]
            if actual != wanted:
                return FlagObservation(ObservationStatus.MISMATCH, value=actual)
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        except Exception as error:  # noqa: BLE001 - retrieval is observational
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=f"execution observation failed: {type(error).__name__}",
            )

    def flag_id(self, handle: str) -> str | None:
        return public_locator(handle)
