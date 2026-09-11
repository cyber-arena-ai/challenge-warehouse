"""Baseline principals and READ/EXECUTE objective placement."""

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
    VulboxTarget,
    exec_read_observe,
)

from ._api import SuiteCrmClient, resolve_host
from ._ids import (
    STORE_COMMAND,
    STORE_PRIVATE_NOTE,
    derive_principal,
    objective_command,
    pack_handle,
    public_flag_id,
    unpack_handle,
    valid_operation,
    valid_uuid,
)

OBJECTIVE_DIR = "/opt/arena/objective"
OBJECTIVE_PATH = OBJECTIVE_DIR + "/current"
CACHE_DIR = "/arena/state/plants"


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


class SuiteCrmFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "suitecrm-security-groups-flag-handler"

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    def _api(self, target: VulboxTarget) -> SuiteCrmClient:
        return SuiteCrmClient(
            f"http://{resolve_host(target.host)}:{target.ports['service']}"
        )

    def provision_principals(
        self,
        target: VulboxTarget,
        seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        self._wait_ready(target)
        principals: dict[str, BaselinePrincipal] = {}
        users: list[dict[str, str]] = []
        for attacker, seed in sorted(seeds.items()):
            username, password, group = derive_principal(seed)
            users.append({
                "username": username,
                "password": password,
                "group": group,
            })
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )

        rc, out = self._exec(
            target,
            f"/arena/facility.py principals {_b64(json.dumps(users, separators=(',', ':')))}",
        )
        try:
            result = json.loads((out or "").strip()) if rc == 0 else {}
            client_id = result["client_id"]
            client_secret = result["client_secret"]
            if result.get("count") != len(users):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(f"{self.name}: principal provisioning failed") from error

        issued: dict[str, BaselinePrincipal] = {}
        for attacker, principal in principals.items():
            credentials = dict(principal.credentials)
            credentials.update({
                "client_id": str(client_id),
                "client_secret": str(client_secret),
            })
            api = self._api(target)
            if not api.login(credentials["username"], credentials["password"]):
                raise RuntimeError(f"{self.name}: provisioned principal rejected")
            if not api.oauth_login(
                credentials["client_id"], credentials["client_secret"],
                credentials["username"], credentials["password"],
            ):
                raise RuntimeError(f"{self.name}: provisioned OAuth rejected")
            issued[attacker] = BaselinePrincipal(
                principal_id=principal.principal_id,
                credentials=credentials,
            )
        return issued

    def _wait_ready(self, target: VulboxTarget) -> None:
        rc, _ = self._exec(
            target,
            "for i in $(seq 1 1500); do "
            "test -f /run/suitecrm/arena.ready && exit 0; "
            "sleep .1; done; exit 1",
        )
        if rc != 0:
            raise RuntimeError("SuiteCRM did not become ready for flag placement")

    def plant(
        self,
        target: VulboxTarget,
        flags: Mapping[str, Flag],
    ) -> Mapping[str, str]:
        expected = {STORE_PRIVATE_NOTE, STORE_COMMAND}
        if set(flags) != expected:
            raise ValueError(f"expected stores {sorted(expected)}, got {sorted(flags)}")
        self._wait_ready(target)
        return {
            STORE_COMMAND: self._plant_command(
                target, flags[STORE_COMMAND].value
            ),
            STORE_PRIVATE_NOTE: self._plant_note(
                target, flags[STORE_PRIVATE_NOTE].value
            ),
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
        if payload and payload.get("store") == store and payload.get("flag") == value:
            return handle
        return None

    def _cache(
        self,
        target: VulboxTarget,
        store: str,
        value: str,
        handle: str,
    ) -> None:
        key = self._cache_key(store, value)
        command = (
            f"install -d -o root -g root -m 0700 {CACHE_DIR}; "
            f"printf %s {_b64(handle)} | base64 -d > {CACHE_DIR}/{key}.new; "
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
            "store": STORE_COMMAND,
            "target": operation,
            "flag": value,
        })
        self._cache(target, STORE_COMMAND, value, handle)
        return handle

    def _plant_note(self, target: VulboxTarget, value: str) -> str:
        cached = self._cached(target, STORE_PRIVATE_NOTE, value)
        if cached:
            return cached
        rc, out = self._exec(
            target, f"/arena/facility.py plant-note {_b64(value)}"
        )
        note_id = ((out or "").strip().splitlines() or [""])[-1]
        if rc != 0 or not valid_uuid(note_id):
            raise RuntimeError("private-note placement failed")
        handle = pack_handle({
            "store": STORE_PRIVATE_NOTE,
            "target": note_id,
            "flag": value,
        })
        self._cache(target, STORE_PRIVATE_NOTE, value, handle)
        return handle

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        payload = unpack_handle(handle)
        if payload is None:
            return FlagObservation(ObservationStatus.ERROR, detail="unreadable handle")
        wanted = expected if expected is not None else payload.get("flag")
        target_id = payload.get("target")
        if payload.get("store") == STORE_COMMAND:
            if not valid_operation(target_id):
                return FlagObservation(
                    ObservationStatus.ERROR, detail="invalid operation id"
                )
            return exec_read_observe(
                target, objective_command(target_id), wanted
            )
        if payload.get("store") != STORE_PRIVATE_NOTE or not valid_uuid(target_id):
            return FlagObservation(ObservationStatus.ERROR, detail="unknown store")
        try:
            rc, out = self._exec(
                target, f"/arena/facility.py read-note {target_id}"
            )
        except Exception:  # noqa: BLE001 — retrieve must never raise
            return FlagObservation(
                ObservationStatus.ERROR, detail="guarded read exec raised"
            )
        if rc == 3:
            return FlagObservation(
                ObservationStatus.AUTH_REJECTED,
                detail="guarded identity rejected",
            )
        if rc == 4:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if rc != 0:
            return FlagObservation(
                ObservationStatus.ERROR, detail=f"guarded read rc={rc}"
            )
        actual = (out or "").rstrip("\n")
        if actual == wanted:
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        return FlagObservation(ObservationStatus.MISMATCH)

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
