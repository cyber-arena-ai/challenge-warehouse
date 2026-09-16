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


class MarimoExecutionFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "marimo-notebook-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    @staticmethod
    def _invoke(
        target: VulboxTarget, operation: str, payload: object
    ) -> tuple[int, str]:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            raise RuntimeError("facility exec bridge is unavailable")
        encoded = _encoded(payload)
        command = (
            f"printf %s {shlex.quote(encoded)} | "
            f"/arena/facility.py {shlex.quote(operation)}"
        )
        rc, output = exec_in(target.host, command)
        return rc, output or ""

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected exactly {STORE!r}")
        proof = flags[STORE].value
        if (
            not isinstance(proof, str)
            or not proof
            or "\n" in proof
            or len(proof) > 512
        ):
            raise ValueError("invalid execution proof shape")
        seed = target.meta.get("round_context_seed")
        if not isinstance(seed, str):
            raise ValueError("round_context_seed is required")
        generation = {
            **round_context(seed),
            "store": STORE,
            "token": proof,
        }
        rc, output = self._invoke(target, "plant", generation)
        if rc != 0 or (output or "").strip() != "OK":
            tail = (output or "no detail").strip().splitlines()[-1]
            raise RuntimeError(
                f"execution witness placement failed (rc={rc}): {tail[:240]}"
            )
        return {STORE: pack_handle(generation)}

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        generation = unpack_handle(handle)
        if generation is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        wanted = expected if expected is not None else generation["token"]
        if not isinstance(wanted, str) or not wanted:
            return FlagObservation(
                ObservationStatus.ERROR, detail="invalid expected value"
            )
        try:
            rc, output = self._invoke(
                target, "observe", {"operation": generation["operation"]}
            )
        except Exception as error:  # noqa: BLE001 - observation must return a fact
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=f"execution observation failed: {type(error).__name__}",
            )
        if rc == 4:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if rc != 0:
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=f"execution witness returned rc={rc}",
            )
        actual = (output or "").rstrip("\n")
        if actual != wanted:
            return FlagObservation(ObservationStatus.MISMATCH, value=actual)
        return FlagObservation(ObservationStatus.PRESENT, value=actual)

    def flag_id(self, handle: str) -> str | None:
        return public_locator(handle)
