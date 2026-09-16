"""Provision native device principals and rotate one retained MQTT objective."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Mapping

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    VulboxTarget,
)

from ._ids import (
    ISSUED_COHORT_FILE,
    derive_principal,
    facility_publisher,
    issued_cohort,
    pack_handle,
    public_flag_id,
    round_context,
    unpack_handle,
    valid_target,
)


def _b64_json(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.b64encode(raw).decode()


class NatsFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "nats-mqtt-acl-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    def provision_principals(
        self,
        target: VulboxTarget,
        seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        principals: dict[str, BaselinePrincipal] = {}
        team_id = str(target.meta["team_id"])
        requested: list[dict[str, str]] = []
        for attacker, seed in sorted(seeds.items()):
            username, password = derive_principal(seed)
            requested.append({"username": username, "password": password})
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        usernames = [row["username"] for row in requested]
        if len(usernames) != len(set(usernames)):
            raise RuntimeError("ordinary principal identity collision")
        publisher_id, publisher_password = facility_publisher(team_id)
        request = {
            "victim": {
                "username": publisher_id,
                "password": publisher_password,
            },
            "devices": requested,
        }
        rc, output = self._exec(
            target, "/arena/facility.py principals " + _b64_json(request)
        )
        try:
            result = json.loads((output or "").strip()) if rc == 0 else {}
            if result.get("count") != len(requested):
                raise ValueError
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(f"{self.name}: principal provisioning failed") from error
        self._seal_issued_cohort(
            target,
            [(row["username"], row["password"]) for row in requested],
        )
        return principals

    @staticmethod
    def _seal_issued_cohort(
        target: VulboxTarget, principals: list[tuple[str, str]]
    ) -> None:
        sealed = issued_cohort(principals)
        staged = f"{ISSUED_COHORT_FILE}.new"
        encoded = base64.b64encode(sealed.encode()).decode()
        command = "sh -ceu " + shlex.quote(
            f"rm -f {staged}; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {staged}; "
            f"chown root:root {staged}; chmod 0400 {staged}; "
            f"mv -f {staged} {ISSUED_COHORT_FILE}"
        )
        rc, _ = target.meta["exec_in_container"](target.host, command)
        if rc != 0:
            raise RuntimeError("issued principal cohort sealing failed")

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {"retained_secret"}:
            raise ValueError("expected exactly the retained_secret store")
        return {
            "retained_secret": self._plant_one(
                target, flags["retained_secret"].value
            )
        }

    def _plant_one(self, target: VulboxTarget, value: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("retained objective must be a nonempty string")
        context = round_context(target.meta.get("round_context_seed"))
        request = {**context, "value": value}
        rc, output = self._exec(
            target, "/arena/facility.py plant " + _b64_json(request)
        )
        if rc != 0 or (output or "").strip() != "OK":
            raise RuntimeError("retained objective placement failed")
        return pack_handle({
            "store": "retained_secret",
            "target": context["target"],
            "flag": value,
        })

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        try:
            payload = unpack_handle(handle)
            if payload is None or payload.get("store") != "retained_secret":
                return FlagObservation(
                    ObservationStatus.ERROR, detail="unreadable handle"
                )
            target_id = payload.get("target")
            wanted = expected if expected is not None else payload.get("flag")
            if not valid_target(target_id) or not isinstance(wanted, str):
                return FlagObservation(
                    ObservationStatus.ERROR, detail="invalid handle"
                )
            request = _b64_json({"target": target_id})
            rc, output = self._exec(
                target, "/arena/facility.py read " + request
            )
        except Exception:  # retrieve is a read-only audit path and must never raise
            return FlagObservation(
                ObservationStatus.ERROR, detail="retained read failed"
            )
        if rc == 4:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if rc != 0:
            return FlagObservation(
                ObservationStatus.ERROR, detail=f"retained read rc={rc}"
            )
        actual = (output or "").rstrip("\n")
        if actual == wanted:
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        return FlagObservation(ObservationStatus.MISMATCH, value=actual)

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
