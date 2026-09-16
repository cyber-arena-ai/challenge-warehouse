"""Grafana-native principals and WRITE/EXECUTE objective placement."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
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
    checker_contacts,
    checker_principals,
    contact_details,
    derive_principal,
    objective_command,
    pack_handle,
    public_flag_id,
    unpack_handle,
    valid_contact_name,
    valid_contact_uid,
    valid_contact_url,
    valid_operation,
)
from ._state import protected_url, service_account_name

OBJECTIVE_DIR = "/opt/arena/objective"
CACHE_DIR = "/arena/state/plants"
_ROUND_SEED_RE = re.compile(r"[0-9a-f]{64}")
_ANCHOR_NAME_RE = re.compile(r"[0-9a-f]{64}")


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


def _round_value(
    target: VulboxTarget, store: str, purpose: str, length: int = 64,
) -> str:
    seed = target.meta.get("round_context_seed")
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise RuntimeError("round context seed unavailable")
    return hmac.new(
        bytes.fromhex(seed),
        f"grafana-protected-contact-point\0{store}\0{purpose}\0v1".encode(),
        hashlib.sha256,
    ).hexdigest()[:length]


def _group_id(target: VulboxTarget) -> str:
    return _round_value(target, "objective-group", "group-id")


def _anchor_name(token: str, round_material: str) -> str:
    return hashlib.sha256(
        f"grafana-write-integrity\0{round_material}\0{token}".encode()
    ).hexdigest()


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
            users.append({
                "username": username, "password": password, "role": "Editor",
            })
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        team_id = str(target.meta.get("team_id") or "")
        for authority, role in (("ordinary", "Editor"), ("guarded", "Admin")):
            for username, password in checker_principals(team_id, authority):
                users.append({
                    "username": username, "password": password, "role": role,
                })
        users.sort(key=lambda user: user["username"])
        contacts = [
            {"uid": uid, "name": name, "url": url}
            for uid, name, url in checker_contacts(team_id)
        ]
        contacts.sort(key=lambda contact: contact["uid"])
        rc, out = self._exec(
            target,
            "/arena/facility.py principals "
            + _b64(json.dumps(
                {"users": users, "contacts": contacts}, separators=(",", ":")
            )),
        )
        try:
            result = json.loads((out or "").strip()) if rc == 0 else {}
            if (
                result.get("users") != len(users)
                or result.get("contacts") != len(contacts)
            ):
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
        command = self._prepare_command(target, flags[STORE_COMMAND].value)
        receiver = self._plant_receiver(
            target, flags[STORE_PROTECTED_RECEIVER].value, command
        )
        self._converge_command(target, command)
        self._commit_receiver(target, receiver, command)
        return {
            STORE_PROTECTED_RECEIVER: receiver,
            STORE_COMMAND: command,
        }

    @staticmethod
    def _cache_key(target: VulboxTarget, store: str) -> str:
        group = _group_id(target)
        return _round_value(target, store, f"plant-cache\0{group}")

    def _cached(self, target: VulboxTarget, store: str, value: str) -> str | None:
        key = self._cache_key(target, store)
        rc, out = self._exec(
            target,
            f"if [ -e {CACHE_DIR}/{key} ]; then "
            f"cat {CACHE_DIR}/{key}; else exit 44; fi",
        )
        if rc == 44:
            return None
        if rc != 0:
            raise RuntimeError(f"could not read {store} plant state")
        handle = (out or "").strip()
        payload = unpack_handle(handle)
        if payload and payload.get("store") == store and payload.get("token") == value:
            return handle
        raise RuntimeError(f"cached {store} plant state is invalid")

    def _cache(
        self, target: VulboxTarget, store: str, value: str, handle: str,
    ) -> None:
        key = self._cache_key(target, store)
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

    @staticmethod
    def _receiver_request(
        receiver_handle: str, command_handle: str,
    ) -> dict[str, object]:
        payload = unpack_handle(receiver_handle) or {}
        command = unpack_handle(command_handle) or {}
        uid = payload.get("target")
        name = payload.get("name")
        url = payload.get("url")
        token = payload.get("token")
        org_id = payload.get("org_id")
        anchor_id = payload.get("anchor_id")
        anchor_name = payload.get("anchor_name")
        operation = command.get("target")
        command_token = command.get("token")
        if (
            payload.get("store") != STORE_PROTECTED_RECEIVER
            or not isinstance(token, str)
            or not valid_contact_uid(uid)
            or not valid_contact_name(name)
            or not valid_contact_url(url)
            or org_id != 1
            or not isinstance(anchor_name, str)
            or _ANCHOR_NAME_RE.fullmatch(anchor_name) is None
            or (
                anchor_id is not None
                and (not isinstance(anchor_id, int) or isinstance(anchor_id, bool))
            )
            or command.get("store") != STORE_COMMAND
            or not valid_operation(operation)
            or not isinstance(command_token, str)
        ):
            raise RuntimeError("cached objective-group plant state is invalid")
        return {
            "uid": uid,
            "name": name,
            "url": url,
            "anchor_name": anchor_name,
            "anchor_id": anchor_id,
            "command_operation": operation,
            "command_sha256": hashlib.sha256(command_token.encode()).hexdigest(),
        }

    def _plant_receiver(
        self, target: VulboxTarget, token: str, command_handle: str,
    ) -> str:
        material = _round_value(
            target,
            STORE_PROTECTED_RECEIVER,
            f"target-id\0{_group_id(target)}",
        )
        expected_uid, expected_name, expected_url = contact_details(material)
        expected_anchor_name = _anchor_name(
            token,
            _round_value(
                target,
                STORE_PROTECTED_RECEIVER,
                f"integrity-anchor\0{_group_id(target)}",
            ),
        )
        cached = self._cached(target, STORE_PROTECTED_RECEIVER, token)
        if cached is None:
            cached = pack_handle({
                "store": STORE_PROTECTED_RECEIVER,
                "target": expected_uid,
                "token": token,
                "name": expected_name,
                "url": expected_url,
                "org_id": 1,
                "anchor_id": None,
                "anchor_name": expected_anchor_name,
            })
            self._cache(target, STORE_PROTECTED_RECEIVER, token, cached)
        else:
            payload = unpack_handle(cached) or {}
            if (
                payload.get("target") != expected_uid
                or payload.get("name") != expected_name
                or payload.get("url") != expected_url
                or payload.get("anchor_name") != expected_anchor_name
            ):
                raise RuntimeError("cached receiver target is invalid")
        request = self._receiver_request(cached, command_handle)
        uid = request["uid"]
        name = request["name"]
        url = request["url"]
        anchor_id = request["anchor_id"]
        rc, out = self._exec(
            target,
            "/arena/facility.py stage-receiver "
            + _b64(json.dumps(request, separators=(",", ":"))),
        )
        try:
            result = json.loads((out or "").strip()) if rc == 0 else {}
            result_org_id = result["org_id"]
            result_anchor_id = result["anchor_id"]
            if (
                result_org_id != 1
                or not isinstance(result_anchor_id, int)
                or isinstance(result_anchor_id, bool)
                or (anchor_id is not None and result_anchor_id != anchor_id)
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("protected receiver placement failed") from error
        handle = pack_handle({
            "store": STORE_PROTECTED_RECEIVER,
            "target": uid,
            "token": token,
            "name": name,
            "url": url,
            "org_id": result_org_id,
            "anchor_id": result_anchor_id,
            "anchor_name": expected_anchor_name,
        })
        if handle != cached:
            self._cache(target, STORE_PROTECTED_RECEIVER, token, handle)
        return handle

    def _commit_receiver(
        self, target: VulboxTarget, receiver_handle: str, command_handle: str,
    ) -> None:
        request = self._receiver_request(receiver_handle, command_handle)
        rc, out = self._exec(
            target,
            "/arena/facility.py commit-receiver "
            + _b64(json.dumps(request, separators=(",", ":"))),
        )
        try:
            result = json.loads((out or "").strip()) if rc == 0 else {}
            if result.get("org_id") != 1 or result.get("anchor_id") != request["anchor_id"]:
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("protected receiver commit failed") from error

    def _prepare_command(self, target: VulboxTarget, token: str) -> str:
        expected_operation = _round_value(
            target,
            STORE_COMMAND,
            f"operation-id\0{_group_id(target)}",
            32,
        )
        cached = self._cached(target, STORE_COMMAND, token)
        if cached:
            payload = unpack_handle(cached) or {}
            operation = payload.get("target")
            if not valid_operation(operation) or operation != expected_operation:
                raise RuntimeError("cached command operation id is invalid")
            handle = cached
        else:
            handle = pack_handle({
                "store": STORE_COMMAND,
                "target": expected_operation,
                "token": token,
            })
            self._cache(target, STORE_COMMAND, token, handle)
        return handle

    def _converge_command(self, target: VulboxTarget, handle: str) -> None:
        payload = unpack_handle(handle) or {}
        operation = payload.get("target")
        token = payload.get("token")
        if (
            payload.get("store") != STORE_COMMAND
            or not valid_operation(operation)
            or not isinstance(token, str)
        ):
            raise RuntimeError("cached command operation id is invalid")
        self._write_command_objective(target, str(operation), token)
        observed = self.retrieve(target, handle, expected=token)
        if observed.status is not ObservationStatus.PRESENT:
            raise RuntimeError(
                "command objective could not be restored through its operation"
            )

    def _write_command_objective(
        self, target: VulboxTarget, operation: str, token: str,
    ) -> None:
        encoded = _b64(f"{operation}\n{token}\n")
        command = (
            f"install -d -o root -g root -m 0700 {OBJECTIVE_DIR}; "
            f"printf %s {encoded} | base64 -d > {OBJECTIVE_DIR}/{operation}.new; "
            f"chown root:root {OBJECTIVE_DIR}/{operation}.new; "
            f"chmod 0600 {OBJECTIVE_DIR}/{operation}.new; "
            f"mv -f {OBJECTIVE_DIR}/{operation}.new {OBJECTIVE_DIR}/{operation}"
        )
        rc, _ = self._exec(target, command)
        if rc != 0:
            raise RuntimeError("command objective placement failed")

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
        anchor_name = payload.get("anchor_name")
        if (
            org_id != 1
            or not isinstance(anchor_id, int)
            or isinstance(anchor_id, bool)
            or not isinstance(anchor_name, str)
            or _ANCHOR_NAME_RE.fullmatch(anchor_name) is None
        ):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid anchor handle")
        raw, detail = self._snapshot(target)
        if raw is None:
            return FlagObservation(ObservationStatus.ERROR, detail=detail)
        try:
            if wanted == token:
                actual = service_account_name(raw, org_id, anchor_id)
                if actual is None:
                    return FlagObservation(ObservationStatus.NOT_FOUND)
                if actual == anchor_name:
                    return FlagObservation(ObservationStatus.PRESENT, value=token)
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
