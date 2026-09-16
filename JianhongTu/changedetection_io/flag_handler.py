"""Rotate the application's existing Flask session-signing credential."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Mapping

from challenges.interface import (
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
    exec_read_observe,
)

from ._ids import pack_handle, public_flag_id, round_target, unpack_handle


class ChangedetectionIoFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "changedetection-io-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {"session_secret"}:
            raise ValueError("expected exactly the session_secret store")
        flag = flags["session_secret"].value
        if not isinstance(flag, str) or not flag or "\n" in flag:
            raise ValueError("session credential must be a nonempty single line")
        target_id = round_target(target.meta.get("round_context_seed"))
        request = base64.b64encode(
            json.dumps(
                {"flag": flag, "target": target_id}, separators=(",", ":")
            ).encode()
        ).decode()
        rc, output = self._exec(
            target, "/arena/facility.py plant " + shlex.quote(request)
        )
        if rc != 0 or (output or "").strip() != "OK":
            raise RuntimeError("session credential placement failed")
        return {"session_secret": pack_handle(target_id, flag)}

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        payload = unpack_handle(handle)
        if payload is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        wanted = expected if expected is not None else payload["flag"]
        if not isinstance(wanted, str) or not wanted:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid expected value")
        return exec_read_observe(
            target, f"cat {shlex.quote(payload['target'])}", wanted
        )

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
