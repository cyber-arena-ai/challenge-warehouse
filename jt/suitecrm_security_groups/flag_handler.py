"""Baseline principals and READ/EXECUTE objective placement."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import uuid
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
from .checker_identity import (
    COHORT_PATH,
    checker_setup,
    private_identity_context,
    seal_cohort,
)
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
CACHE_DIR = "/arena/state/plants"
_GROUP_FIELDS = (
    "group", "note", "operation", "note_digest", "command_digest",
    "note_cache", "command_cache",
)
_ROUND_SEED_RE = re.compile(r"[0-9a-f]{64}")


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


def _group_digest(target: VulboxTarget, store: str, value: str) -> str:
    secret, team_id = private_identity_context(target)
    return hmac.new(
        secret.encode(),
        f"suitecrm-security-groups\0{team_id}\0group:{store}\0{value}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _round_context(seed: str) -> dict[str, str]:
    """Derive the atomic group and each proof-independent objective identity."""
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise ValueError("round context seed is unavailable")
    key = bytes.fromhex(seed)

    def derive(label: str) -> bytes:
        return hmac.new(
            key,
            f"suitecrm-security-groups\0{label}\0v1".encode(),
            hashlib.sha256,
        ).digest()

    return {
        "group": derive("objective-group:identity").hex(),
        "note": str(uuid.UUID(
            bytes=derive(f"{STORE_PRIVATE_NOTE}:target")[:16], version=4,
        )),
        "operation": derive(f"{STORE_COMMAND}:target").hex()[:32],
        "note_cache": derive(f"{STORE_PRIVATE_NOTE}:placement-cache").hex(),
        "command_cache": derive(f"{STORE_COMMAND}:placement-cache").hex(),
    }


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

        setup = checker_setup(target)
        for key in ("ordinary", "guarded"):
            for username, password, group in setup[key]:
                users.append({
                    "username": username,
                    "password": password,
                    "group": group,
                })

        self._provision_accounts(target, users, setup)

        issued: dict[str, BaselinePrincipal] = {}
        for attacker, principal in principals.items():
            credentials = dict(principal.credentials)
            credentials.update({
                "client_id": str(setup["client_id"]),
                "client_secret": str(setup["client_secret"]),
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
        self._seal_cohort(target, [
            [principal.credentials["username"], principal.credentials["password"]]
            for principal in issued.values()
        ])
        return issued

    def _seal_cohort(
        self, target: VulboxTarget, accounts: list[list[str]]
    ) -> None:
        """Record the issued cohort under the facility seal health verifies."""

        sealed = _b64(seal_cohort(target, accounts))
        command = (
            f"printf %s {sealed} | base64 -d > {COHORT_PATH}.new; "
            f"chown root:root {COHORT_PATH}.new; "
            f"chmod 0400 {COHORT_PATH}.new; "
            f"mv -f {COHORT_PATH}.new {COHORT_PATH}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError(f"{self.name}: issued cohort seal failed")

    def _provision_accounts(
        self,
        target: VulboxTarget,
        users: list[dict[str, str]],
        setup: dict[str, object],
    ) -> None:
        rc, out = self._exec(
            target,
            "/arena/facility.py principals "
            + _b64(json.dumps({
                "accounts": users,
                "checker": {
                    "ordinary": [principal[0] for principal in setup["ordinary"]],
                    "guarded": [principal[0] for principal in setup["guarded"]],
                },
                "client": {
                    "id": setup["client_id"],
                    "secret": setup["client_secret"],
                },
            }, separators=(",", ":"), sort_keys=True)),
        )
        try:
            result = json.loads((out or "").strip()) if rc == 0 else {}
            if result.get("count") != len(users):
                raise ValueError
            if result.get("client_id") != setup["client_id"]:
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(f"{self.name}: principal provisioning failed") from error

    def _provision_checkers(
        self, target: VulboxTarget, setup: dict[str, object]
    ) -> None:
        users = []
        for key in ("ordinary", "guarded"):
            for username, password, group in setup[key]:
                users.append({
                    "username": username,
                    "password": password,
                    "group": group,
                })
        self._provision_accounts(target, users, setup)

    def plant(
        self,
        target: VulboxTarget,
        flags: Mapping[str, Flag],
    ) -> Mapping[str, str]:
        expected = {STORE_PRIVATE_NOTE, STORE_COMMAND}
        if set(flags) != expected:
            raise ValueError(f"expected stores {sorted(expected)}, got {sorted(flags)}")
        command_value = flags[STORE_COMMAND].value
        note_value = flags[STORE_PRIVATE_NOTE].value
        context = _round_context(target.meta.get("round_context_seed", ""))

        api = self._guarded_api(target, repair=True)
        state = self._resume_group(target, api)
        command_handle, command = self._handle(
            target,
            STORE_COMMAND,
            command_value,
            context["operation"],
            context["command_cache"],
        )
        note_handle, note = self._handle(
            target,
            STORE_PRIVATE_NOTE,
            note_value,
            context["note"],
            context["note_cache"],
        )
        operation = command["target"]
        note_id = note["target"]
        note_digest = _group_digest(target, STORE_PRIVATE_NOTE, note_value)
        command_digest = _group_digest(target, STORE_COMMAND, command_value)

        requested = {
            "group": context["group"],
            "note": note_id,
            "operation": operation,
            "note_digest": note_digest,
            "command_digest": command_digest,
            "note_cache": context["note_cache"],
            "command_cache": context["command_cache"],
        }
        pending = state["pending"]
        if pending is not None:
            raise RuntimeError("pending objective group did not converge")
        if state["current"] == requested:
            self._converge_note(api, note_id, note_value)
            if self._command_generation(target, operation) != command_value:
                self._publish_command(target, operation, command_value)
            return {
                STORE_COMMAND: command_handle,
                STORE_PRIVATE_NOTE: note_handle,
            }

        self._record_pending(target, requested, state["current"])
        self._converge_note(api, note_id, note_value)
        self._publish_command(target, operation, command_value)
        self._promote_pending(target, requested)
        state = self._group_state(target)
        if state["retiring"]:
            self._finish_retirement(target, api, state["retiring"])
        return {
            STORE_COMMAND: command_handle,
            STORE_PRIVATE_NOTE: note_handle,
        }

    def _cached(
        self,
        target: VulboxTarget,
        store: str,
        value: str,
        target_id: str,
        cache_key: str,
    ) -> tuple[str, dict[str, str]] | None:
        cached = self._cached_by_key(target, cache_key)
        if cached is None:
            return None
        handle, payload = cached
        cached_target = payload.get("target")
        valid_target = (
            valid_operation(cached_target)
            if store == STORE_COMMAND
            else valid_uuid(cached_target)
        )
        if (
            payload.get("store") != store
            or payload.get("flag") != value
            or cached_target != target_id
            or not valid_target
        ):
            raise RuntimeError(f"{store} cached identity is irreconstructible")
        return handle, payload

    def _cached_by_key(
        self, target: VulboxTarget, key: str
    ) -> tuple[str, dict[str, str]] | None:
        if re.fullmatch(r"[0-9a-f]{64}", key) is None:
            raise RuntimeError("plant-state cache identity is invalid")
        rc, out = self._exec(
            target,
            f"if [ ! -e {CACHE_DIR}/{key} ]; then exit 44; fi; "
            f"test -s {CACHE_DIR}/{key} || exit 45; cat {CACHE_DIR}/{key}",
        )
        if rc == 44:
            return None
        if rc != 0:
            raise RuntimeError("plant-state integrity failure")
        handle = (out or "").strip()
        payload = unpack_handle(handle)
        if payload is None:
            raise RuntimeError("cached identity is irreconstructible")
        return handle, payload

    def _cache(
        self,
        target: VulboxTarget,
        store: str,
        cache_key: str,
        handle: str,
    ) -> None:
        command = (
            f"install -d -o root -g root -m 0700 {CACHE_DIR}; "
            f"printf %s {_b64(handle)} | base64 -d > {CACHE_DIR}/{cache_key}.new; "
            f"chmod 0600 {CACHE_DIR}/{cache_key}.new; "
            f"mv -f {CACHE_DIR}/{cache_key}.new {CACHE_DIR}/{cache_key}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError(f"could not persist {store} plant state")

    def _handle(
        self,
        target: VulboxTarget,
        store: str,
        value: str,
        target_id: str,
        cache_key: str,
    ) -> tuple[str, dict[str, str]]:
        cached = self._cached(target, store, value, target_id, cache_key)
        if cached:
            return cached
        payload = {"store": store, "target": target_id, "flag": value}
        handle = pack_handle(payload)
        self._cache(target, store, cache_key, handle)
        return handle, payload

    def _publish_command(
        self, target: VulboxTarget, operation: str, value: str
    ) -> None:
        encoded = _b64(f"{operation}\n{value}\n")
        path = f"{OBJECTIVE_DIR}/{operation}"
        command = (
            f"install -d -o root -g root -m 0700 {OBJECTIVE_DIR}; "
            f"printf %s {encoded} | base64 -d > {path}.new; "
            f"chown root:root {path}.new; "
            f"chmod 0600 {path}.new; "
            f"mv -f {path}.new {path}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError("command objective placement failed")

    def _command_generation(
        self, target: VulboxTarget, operation: str
    ) -> str | None:
        if not valid_operation(operation):
            raise RuntimeError("invalid command operation id")
        path = f"{OBJECTIVE_DIR}/{operation}"
        rc, out = self._exec(
            target,
            f"if [ ! -e {path} ]; then exit 44; fi; "
            f"test -f {path} && test -s {path} || exit 45; "
            f"cat {path}",
        )
        if rc == 44:
            return None
        lines = (out or "").splitlines() if rc == 0 else []
        if (
            rc != 0
            or len(lines) != 2
            or lines[0] != operation
            or not lines[1]
        ):
            raise RuntimeError("command objective state integrity failure")
        return lines[1]

    def _group_state(
        self, target: VulboxTarget
    ) -> dict[str, dict[str, str] | None]:
        rc, out = self._exec(target, "/arena/facility.py read-group-state")
        try:
            state = json.loads((out or "").strip()) if rc == 0 else None
        except json.JSONDecodeError as error:
            raise RuntimeError("objective-group target-state integrity failure") from error
        if (
            not isinstance(state, dict)
            or set(state) != {"current", "previous", "pending", "retiring"}
            or any(
                group is not None and not self._valid_group(group)
                for group in state.values()
            )
            or len({
                group["note"] for group in state.values() if group is not None
            }) != len([group for group in state.values() if group is not None])
            or len({
                group["operation"] for group in state.values() if group is not None
            }) != len([group for group in state.values() if group is not None])
            or (
                state["retiring"] is not None
                and (
                    state["current"] is None
                    or state["previous"] is None
                    or state["pending"] is not None
                )
            )
        ):
            raise RuntimeError("objective-group target-state integrity failure")
        return state

    @staticmethod
    def _valid_group(value: object) -> bool:
        return bool(
            isinstance(value, dict)
            and set(value) == set(_GROUP_FIELDS)
            and isinstance(value.get("group"), str)
            and re.fullmatch(r"[0-9a-f]{64}", value["group"])
            and valid_uuid(value.get("note"))
            and valid_operation(value.get("operation"))
            and isinstance(value.get("note_digest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", value["note_digest"])
            and isinstance(value.get("command_digest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", value["command_digest"])
            and isinstance(value.get("note_cache"), str)
            and re.fullmatch(r"[0-9a-f]{64}", value["note_cache"])
            and isinstance(value.get("command_cache"), str)
            and re.fullmatch(r"[0-9a-f]{64}", value["command_cache"])
        )

    def _record_pending(
        self,
        target: VulboxTarget,
        group: dict[str, str],
        current: dict[str, str] | None,
    ) -> None:
        expected = (
            [
                current[key]
                for key in _GROUP_FIELDS
            ]
            if current is not None
            else ["NONE"] * len(_GROUP_FIELDS)
        )
        rc, _ = self._exec(
            target,
            "/arena/facility.py record-pending "
            + " ".join(group[key] for key in _GROUP_FIELDS)
            + " "
            + " ".join(expected),
        )
        if rc != 0:
            raise RuntimeError("objective-group journal persistence failed")

    def _promote_pending(
        self,
        target: VulboxTarget,
        group: dict[str, str],
    ) -> None:
        rc, _ = self._exec(
            target,
            "/arena/facility.py promote-pending "
            + " ".join(group[key] for key in _GROUP_FIELDS),
        )
        if rc != 0:
            raise RuntimeError("objective-group journal promotion failed")

    def _finish_retirement(
        self,
        target: VulboxTarget,
        api: SuiteCrmClient,
        group: dict[str, str],
    ) -> None:
        note_id = group["note"]
        rows = api.get_entry("Notes", note_id, ["id", "filename"])
        if any(
            row.get("id") == note_id and "filename" in row
            for row in rows
        ):
            api.set_entry("Notes", {"id": note_id, "deleted": "1"})
        rc, _ = self._exec(
            target,
            "/arena/facility.py finish-retirement "
            + " ".join(group[key] for key in _GROUP_FIELDS),
        )
        if rc != 0:
            raise RuntimeError("objective-group retirement persistence failed")

    def _resume_group(
        self, target: VulboxTarget, api: SuiteCrmClient
    ) -> dict[str, dict[str, str] | None]:
        state = self._group_state(target)
        if state["retiring"]:
            self._finish_retirement(target, api, state["retiring"])
            state = self._group_state(target)
        pending = state["pending"]
        if pending is not None:
            note_value = self._cached_group_value(
                target, STORE_PRIVATE_NOTE, pending["note"],
                pending["note_digest"], pending["note_cache"],
            )
            command_value = self._cached_group_value(
                target, STORE_COMMAND, pending["operation"],
                pending["command_digest"], pending["command_cache"],
            )
            self._converge_note(api, pending["note"], note_value)
            self._publish_command(target, pending["operation"], command_value)
            self._promote_pending(target, pending)
            state = self._group_state(target)
            if state["retiring"]:
                self._finish_retirement(target, api, state["retiring"])
                state = self._group_state(target)
        return state

    def _cached_group_value(
        self,
        target: VulboxTarget,
        store: str,
        target_id: str,
        digest: str,
        cache_key: str,
    ) -> str:
        cached = self._cached_by_key(target, cache_key)
        if cached is None:
            raise RuntimeError("pending objective group cache is unavailable")
        _, payload = cached
        value = payload.get("flag")
        if (
            payload.get("store") != store
            or payload.get("target") != target_id
            or not isinstance(value, str)
            or not value
            or not hmac.compare_digest(_group_digest(target, store, value), digest)
        ):
            raise RuntimeError("pending objective group cache is invalid")
        return value

    @staticmethod
    def _note_fields(api: SuiteCrmClient, value: str) -> dict[str, str]:
        return {
            "name": "Customer attachment metadata",
            "description": "Restricted customer attachment metadata",
            "filename": value,
            "file_mime_type": "application/octet-stream",
            "assigned_user_id": api.user_id,
            "deleted": "0",
        }

    def _converge_note(
        self, api: SuiteCrmClient, note_id: str, value: str
    ) -> None:
        fields = {"id": note_id, **self._note_fields(api, value)}
        rows = api.get_entry("Notes", note_id, ["id", "filename"])
        if any(
            row.get("id") == note_id and "filename" in row
            for row in rows
        ):
            api.set_entry("Notes", fields)
        else:
            api.set_entry("Notes", {**fields, "new_with_id": "1"})
        rows = api.get_entry("Notes", note_id, ["id", "filename"])
        if not any(
            row.get("id") == note_id and row.get("filename") == value
            for row in rows
        ):
            raise RuntimeError("private-note convergence failed")

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
        if payload.get("store") != STORE_PRIVATE_NOTE or not valid_uuid(target_id):
            return FlagObservation(ObservationStatus.ERROR, detail="unknown store")
        try:
            api = self._guarded_api(target)
            rows = api.get_entry("Notes", target_id, ["id", "filename"])
        except Exception as error:  # noqa: BLE001
            return FlagObservation(
                ObservationStatus.ERROR, detail=f"guarded read failed: {error}"
            )
        actual = next(
            (row.get("filename") for row in rows if row.get("id") == target_id),
            None,
        )
        if actual is None:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if actual == wanted:
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        return FlagObservation(ObservationStatus.MISMATCH)

    def _guarded_api(
        self, target: VulboxTarget, *, repair: bool = False
    ) -> SuiteCrmClient:
        setup = checker_setup(target)
        username, password, _ = setup["guarded"][0]
        api = self._api(target)
        if api.login(username, password):
            return api
        if repair:
            self._provision_checkers(target, setup)
            api = self._api(target)
        if not api.login(username, password):
            raise RuntimeError("guarded application identity rejected")
        return api

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
