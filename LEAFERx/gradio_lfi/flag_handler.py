"""Native principals and convergent proof-file placement for Gradio."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import json
import shlex

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
)

from ._ids import (
    STORE,
    issued_cohort,
    pack_handle,
    principal_credentials,
    public_locator,
    round_context,
    unpack_handle,
)


def _encoded(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > 16_384:
        raise ValueError("facility payload is too large")
    return base64.b64encode(raw).decode()


class GradioFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "gradio-component-read-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    @staticmethod
    def _invoke(
        target: VulboxTarget, operation: str, payload: object
    ) -> tuple[int, str]:
        if operation not in {"principals", "plant", "observe"}:
            raise ValueError("unknown facility operation")
        exec_in = target.meta.get("exec_in_container")
        if not callable(exec_in):
            raise RuntimeError("facility exec bridge is unavailable")
        command = (
            f"/arena/facility.py {shlex.quote(operation)} "
            f"{shlex.quote(_encoded(payload))}"
        )
        rc, output = exec_in(target.host, command)
        return rc, output or ""

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        principals: dict[str, BaselinePrincipal] = {}
        accounts: list[dict[str, str]] = []
        for attacker, seed in sorted(seeds.items()):
            username, password = principal_credentials(seed)
            accounts.append({"username": username, "password": password})
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        if len({row["username"] for row in accounts}) != len(accounts):
            raise RuntimeError("derived Gradio principal identity collision")
        rc, output = self._invoke(
            target,
            "principals",
            {
                "accounts": accounts,
                "cohort": issued_cohort(
                    [[row["username"], row["password"]] for row in accounts]
                ),
            },
        )
        if rc != 0 or output.strip() != "OK":
            raise RuntimeError(f"Gradio principal provisioning failed (rc={rc})")
        return principals

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected exactly {STORE!r}")
        context = round_context(target.meta.get("round_context_seed"))
        token = flags[STORE].value
        if (
            not isinstance(token, str)
            or not token
            or "\n" in token
            or len(token) > 512
        ):
            raise ValueError("invalid proof shape")
        generation = {**context, "store": STORE, "token": token}
        rc, output = self._invoke(target, "plant", generation)
        if rc != 0 or output.strip() != "OK":
            raise RuntimeError(f"Gradio proof placement failed (rc={rc})")
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
                ObservationStatus.ERROR, detail="invalid expected proof"
            )
        request = {
            key: generation[key]
            for key in ("context", "store", "target_id", "target_path")
        }
        try:
            rc, output = self._invoke(target, "observe", request)
        except Exception as error:  # noqa: BLE001 - retrieval returns observations
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=f"proof observation failed: {type(error).__name__}",
            )
        if rc == 4:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if rc != 0:
            return FlagObservation(
                ObservationStatus.ERROR, detail=f"proof observation returned rc={rc}"
            )
        actual = output.rstrip("\n")
        if actual != wanted:
            return FlagObservation(ObservationStatus.MISMATCH, value=actual)
        return FlagObservation(ObservationStatus.PRESENT, value=actual)

    def flag_id(self, handle: str) -> str | None:
        return public_locator(handle)
