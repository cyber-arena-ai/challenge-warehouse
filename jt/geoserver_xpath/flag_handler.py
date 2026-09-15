"""GeoServer-native principal and READ/EXECUTE objective placement."""

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

from ._ids import (
    STORE_COMMAND,
    STORE_PROTECTED_FEATURE,
    derive_principal,
    feature_id,
    feature_target,
    objective_command,
    pack_handle,
    public_flag_id,
    unpack_handle,
    valid_operation,
)

OBJECTIVE_DIR = "/opt/arena/objective"
OBJECTIVE_PATH = OBJECTIVE_DIR + "/current"
CACHE_DIR = "/arena/state/plants"


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


class GeoServerFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "geoserver-xpath-flag-handler"

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    def provision_principals(
        self,
        target: VulboxTarget,
        seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        principals: dict[str, BaselinePrincipal] = {}
        users: list[dict[str, str]] = []
        for attacker, seed in sorted(seeds.items()):
            username, password = derive_principal(seed)
            users.append({"username": username, "password": password})
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
            if result.get("count") != len(users):
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(f"{self.name}: principal provisioning failed") from error

        return principals

    def plant(
        self,
        target: VulboxTarget,
        flags: Mapping[str, Flag],
    ) -> Mapping[str, str]:
        expected = {STORE_PROTECTED_FEATURE, STORE_COMMAND}
        if set(flags) != expected:
            raise ValueError(f"expected stores {sorted(expected)}, got {sorted(flags)}")
        return {
            STORE_COMMAND: self._plant_command(target, flags[STORE_COMMAND].value),
            STORE_PROTECTED_FEATURE: self._plant_feature(
                target, flags[STORE_PROTECTED_FEATURE].value
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
            "store": STORE_COMMAND,
            "target": operation,
            "flag": value,
        })
        self._cache(target, STORE_COMMAND, value, handle)
        return handle

    def _plant_feature(self, target: VulboxTarget, value: str) -> str:
        rc, out = self._exec(
            target, f"/arena/facility.py plant-feature {_b64(value)}"
        )
        raw_feature = ((out or "").strip().splitlines() or [""])[-1]
        try:
            public_target = feature_target(raw_feature)
        except ValueError as error:
            raise RuntimeError("protected-feature placement failed") from error
        if rc != 0:
            raise RuntimeError("protected-feature placement failed")
        return pack_handle({
            "store": STORE_PROTECTED_FEATURE,
            "target": public_target,
            "flag": value,
        })

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
            return exec_read_observe(target, objective_command(target_id), wanted)
        if payload.get("store") != STORE_PROTECTED_FEATURE:
            return FlagObservation(ObservationStatus.ERROR, detail="unknown store")
        raw_feature = feature_id(target_id)
        if raw_feature is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid feature id")
        try:
            rc, out = self._exec(
                target, f"/arena/facility.py read-feature {raw_feature}"
            )
        except Exception:  # noqa: BLE001 — retrieve must never raise
            return FlagObservation(
                ObservationStatus.ERROR, detail="guarded read exec raised"
            )
        if rc == 3:
            return FlagObservation(
                ObservationStatus.AUTH_REJECTED, detail="guarded identity rejected"
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
