"""Grafana-native principals and WRITE/EXECUTE objective placement."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Mapping

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    StateReadStatus,
    VulboxTarget,
    exec_read_observe,
    read_authoritative_state,
)

from ._ids import (
    STATE_REGION,
    STORE_COMMAND,
    STORE_PROTECTED_RECEIVER,
    derive_principal,
    objective_command,
    pack_handle,
    public_flag_id,
    unpack_handle,
    valid_contact_uid,
    valid_operation,
)
from ._state import protected_url, service_account_name

OBJECTIVE_DIR = "/opt/arena/objective"
OBJECTIVE_PATH = OBJECTIVE_DIR + "/current"
CACHE_DIR = "/arena/state/plants"


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


class GrafanaFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "grafana-protected-contact-point-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        users: list[dict[str, str]] = []
        principals: dict[str, BaselinePrincipal] = {}
        for attacker, seed in sorted(seeds.items()):
            username, password = derive_principal(seed)
            users.append({"username": username, "password": password})
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        rc, out = self._exec(
            target,
            "/arena/facility.py principals "
            + _b64(json.dumps(users, separators=(",", ":"))),
        )
        try:
            result = json.loads((out or "").strip()) if rc == 0 else {}
            if result.get("count") != len(users):
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(f"{self.name}: principal provisioning failed") from error
        return principals

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag],
    ) -> Mapping[str, str]:
        expected = {STORE_PROTECTED_RECEIVER, STORE_COMMAND}
        if set(flags) != expected:
            raise ValueError(f"expected stores {sorted(expected)}, got {sorted(flags)}")
        return {
            STORE_PROTECTED_RECEIVER: self._plant_receiver(
                target, flags[STORE_PROTECTED_RECEIVER].value
            ),
            STORE_COMMAND: self._plant_command(target, flags[STORE_COMMAND].value),
        }

    @staticmethod
    def _cache_key(store: str, value: str) -> str:
        return hashlib.sha256(f"{store}\0{value}".encode()).hexdigest()

    def _cached(self, target: VulboxTarget, store: str, value: str) -> str | None:
        key = self._cache_key(store, value)
        rc, out = self._exec(
            target, f"test -s {CACHE_DIR}/{key} && cat {CACHE_DIR}/{key}"
        )
        handle = (out or "").strip() if rc == 0 else ""
        payload = unpack_handle(handle)
        if payload and payload.get("store") == store and payload.get("token") == value:
            return handle
        return None

    def _cache(
        self, target: VulboxTarget, store: str, value: str, handle: str,
    ) -> None:
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

    def _plant_receiver(self, target: VulboxTarget, token: str) -> str:
        cached = self._cached(target, STORE_PROTECTED_RECEIVER, token)
        if cached:
            return cached
        uid = "arena-cp-" + secrets.token_hex(12)
        request = {"uid": uid, "anchor_name": token}
        rc, out = self._exec(
            target,
            "/arena/facility.py plant-receiver "
            + _b64(json.dumps(request, separators=(",", ":"))),
        )
        try:
            result = json.loads((out or "").strip()) if rc == 0 else {}
            org_id = result["org_id"]
            anchor_id = result["anchor_id"]
            if org_id != 1 or not isinstance(anchor_id, int):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("protected receiver placement failed") from error
        handle = pack_handle({
            "store": STORE_PROTECTED_RECEIVER,
            "target": uid,
            "token": token,
            "org_id": org_id,
            "anchor_id": anchor_id,
        })
        self._cache(target, STORE_PROTECTED_RECEIVER, token, handle)
        return handle

    def _plant_command(self, target: VulboxTarget, token: str) -> str:
        cached = self._cached(target, STORE_COMMAND, token)
        if cached:
            return cached
        operation = secrets.token_hex(16)
        encoded = _b64(f"{operation}\n{token}\n")
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
            "store": STORE_COMMAND, "target": operation, "token": token,
        })
        self._cache(target, STORE_COMMAND, token, handle)
        return handle

    @staticmethod
    def _snapshot(target: VulboxTarget) -> tuple[bytes | None, str | None]:
        result = read_authoritative_state(target, STATE_REGION)
        if result.status is not StateReadStatus.OK:
            return None, result.detail or "Grafana state unreadable"
        matches = [
            data for name, data in result.files.items()
            if name == "grafana.db" or name.endswith("/grafana.db")
        ]
        if len(matches) != 1:
            return None, "Grafana database snapshot missing or ambiguous"
        return matches[0], None

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None,
    ) -> FlagObservation:
        payload = unpack_handle(handle)
        if payload is None or not isinstance(payload.get("token"), str):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        token = str(payload["token"])
        wanted = expected if expected is not None else token
        store = payload.get("store")
        target_id = payload.get("target")
        if store == STORE_COMMAND:
            if not valid_operation(target_id):
                return FlagObservation(ObservationStatus.ERROR, detail="invalid operation id")
            return exec_read_observe(target, objective_command(str(target_id)), wanted)
        if store != STORE_PROTECTED_RECEIVER or not valid_contact_uid(target_id):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid receiver handle")
        org_id = payload.get("org_id")
        anchor_id = payload.get("anchor_id")
        if org_id != 1 or not isinstance(anchor_id, int) or isinstance(anchor_id, bool):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid anchor handle")
        raw, detail = self._snapshot(target)
        if raw is None:
            return FlagObservation(ObservationStatus.ERROR, detail=detail)
        try:
            if wanted == token:
                actual = service_account_name(raw, org_id, anchor_id)
                if actual is None:
                    return FlagObservation(ObservationStatus.NOT_FOUND)
                if actual == token:
                    return FlagObservation(ObservationStatus.PRESENT, value=actual)
                return FlagObservation(ObservationStatus.MISMATCH)
            url = protected_url(raw, org_id, str(target_id))
        except Exception:  # noqa: BLE001 — retrieve must never raise
            return FlagObservation(ObservationStatus.ERROR, detail="invalid Grafana state")
        if url is None:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if wanted and wanted in url:
            return FlagObservation(ObservationStatus.PRESENT, value=wanted)
        return FlagObservation(ObservationStatus.MISMATCH)

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
