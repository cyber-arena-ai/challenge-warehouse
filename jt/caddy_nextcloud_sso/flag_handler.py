"""Baseline principals and READ/EXECUTE objective placement."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
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

from ._api import NextcloudClient, resolve_host
from .cohort import seal_issued_cohort
from ._ids import (
    CHECKER_HISTORY_MAX,
    CHECKER_LOGIN_LIMIT,
    CHECKER_PRINCIPAL_COUNT,
    STORE_COMMAND,
    STORE_GUARDED_FILE,
    checker_document_owner,
    checker_pair_successor,
    derive_principal,
    guarded_principals,
    guarded_principals_from_material,
    objective_cover_body,
    objective_document_name,
    objective_command,
    pack_handle,
    public_flag_id,
    unpack_handle,
    valid_operation,
    valid_read_target,
)
from .checker import _put_checker_pair, _reconciled_state

OBJECTIVE_DIR = "/opt/arena/objective"
CACHE_DIR = "/arena/state/plants"
_GROUP_FIELDS = (
    "group", "target", "cover", "owner", "cover_after", "operation",
    "read_digest", "command_digest", "read_cache", "command_cache",
)
_ROUND_SEED_RE = re.compile(r"[0-9a-f]{64}")


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


def _group_digest(seed: str, store: str, value: str) -> str:
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise ValueError("round context seed is unavailable")
    return hmac.new(
        bytes.fromhex(seed),
        f"caddy-nextcloud-sso\0group-proof:{store}\0{value}\0v1".encode(),
        hashlib.sha256,
    ).hexdigest()


def _round_context(seed: str) -> dict[str, str | int | bool]:
    """Derive every proof-independent identity for one grouped placement."""
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise ValueError("round context seed is unavailable")
    key = bytes.fromhex(seed)

    def derive(label: str) -> bytes:
        return hmac.new(
            key,
            f"caddy-nextcloud-sso\0{label}\0v1".encode(),
            hashlib.sha256,
        ).digest()

    return {
        "group": derive("objective-group:identity").hex(),
        "target": "Guarded/" + objective_document_name(
            derive(f"{STORE_GUARDED_FILE}:target")
        ),
        "cover": "Guarded/" + objective_document_name(
            derive(f"{STORE_GUARDED_FILE}:cover-target")
        ),
        "owner": derive(f"{STORE_GUARDED_FILE}:owner")[0]
        % CHECKER_PRINCIPAL_COUNT,
        "cover_after": bool(derive(f"{STORE_GUARDED_FILE}:cover-order")[0] & 1),
        "operation": derive(f"{STORE_COMMAND}:target").hex()[:32],
        "read_cache": derive(f"{STORE_GUARDED_FILE}:placement-cache").hex(),
        "command_cache": derive(f"{STORE_COMMAND}:placement-cache").hex(),
    }


def _group_arg(value: dict[str, object] | None) -> str:
    return _b64(json.dumps(value, separators=(",", ":"), sort_keys=True))


def _guarded_owner(payload: dict) -> int:
    owner = payload.get("owner")
    if (isinstance(owner, bool) or not isinstance(owner, int)
            or not 0 <= owner < CHECKER_PRINCIPAL_COUNT):
        raise ValueError("invalid guarded owner")
    return owner


def _guarded_cover_after(payload: dict) -> bool:
    cover_after = payload.get("cover_after")
    if not isinstance(cover_after, bool):
        raise ValueError("invalid guarded cover order")
    return cover_after


def _guarded_cover(payload: dict, target: str) -> tuple[str, bytes]:
    cover = payload.get("cover")
    if not valid_read_target(cover) or cover == target:
        raise ValueError("invalid guarded cover identity")
    return cover, objective_cover_body(cover)


class CaddyNextcloudFlagHandler(FlagHandler):
    def __init__(self) -> None:
        self._provisioned_targets: set[str] = set()
        self._stub_guarded_accounts: dict[
            str, tuple[tuple[str, str], ...]
        ] = {}

    @property
    def name(self) -> str:
        return "caddy-nextcloud-sso-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        principals: dict[str, BaselinePrincipal] = {}
        users: list[dict[str, str]] = []
        issued_accounts: list[tuple[str, str]] = []
        for index, (attacker, seed) in enumerate(sorted(seeds.items())):
            username, password = derive_principal(seed)
            issued_accounts.append((username, password))
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
            users.append({
                "username": username, "password": password, "guarded": False,
                "verify": index == 0,
            })
        sealed = seal_issued_cohort(
            target, [[username, password]
                     for username, password in issued_accounts])
        guarded = guarded_principals(self._team_id(target))
        users.extend({
            "username": username,
            "password": password,
            "guarded": True,
        } for username, password in guarded)
        self._provision(target, users)
        self._seed_checker_documents(target, guarded)
        self._store_issued_cohort(target, sealed)
        self._provisioned_targets.add(self._team_id(target))
        return principals

    @staticmethod
    def _team_id(target: VulboxTarget) -> str:
        team_id = str(target.meta.get("team_id", ""))
        if not team_id:
            raise RuntimeError("target team identity unavailable")
        return team_id

    def _provision(self, target: VulboxTarget,
                   users: list[dict[str, object]]) -> None:
        encoded = _b64(json.dumps(users, separators=(",", ":"), sort_keys=True))
        command = f"/arena/facility.py principals {encoded}"
        deadline = time.monotonic() + 60.0
        delay = 0.25
        stage = "application"
        while True:
            rc, out = self._exec(target, command)
            status = ((out or "").strip().splitlines() or [""])[-1]
            if rc == 0 and status == f"OK {len(users)}":
                return
            match = re.fullmatch(
                r"ERROR stage=([a-z-]+) retryable=([01])", status)
            if match is not None:
                stage = match.group(1)
                if match.group(2) == "0":
                    raise RuntimeError(
                        f"{self.name}: principal provisioning failed "
                        f"permanently at {stage}: rc={rc}")
                if stage == "application-convergence":
                    raise RuntimeError(
                        f"{self.name}: principal provisioning did not converge "
                        f"at {stage}: rc={rc}")
            remaining = deadline - time.monotonic()
            if remaining <= delay:
                raise RuntimeError(
                    f"{self.name}: principal provisioning did not converge "
                    f"at {stage}: rc={rc}")
            time.sleep(delay)
            delay = min(delay * 2, 4.0)

    def _store_issued_cohort(
        self, target: VulboxTarget, sealed: str,
    ) -> None:
        rc, out = self._exec(
            target, f"/arena/facility.py store-issued-cohort {sealed}")
        if rc != 0 or (out or "").strip() != "OK":
            raise RuntimeError("issued principal cohort could not be stored")

    def _ensure_guarded_principals(self, target: VulboxTarget) -> None:
        team_id = self._team_id(target)
        if team_id in self._provisioned_targets:
            return
        try:
            guarded = guarded_principals(team_id)
            seed_documents = True
        except RuntimeError as error:
            if str(error) != "guarded principal material is unavailable":
                raise
            seed = target.meta.get("round_context_seed", "")
            if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
                raise
            material = hmac.new(
                bytes.fromhex(seed),
                b"caddy-nextcloud-sso\0canonical-build-checker-cohort\0v1",
                hashlib.sha256,
            ).hexdigest()
            guarded = guarded_principals_from_material(team_id, material)
            self._stub_guarded_accounts[team_id] = guarded
            seed_documents = False
        users = [{
            "username": username,
            "password": password,
            "guarded": True,
        } for username, password in guarded]
        self._provision(target, users)
        if seed_documents:
            self._seed_checker_documents(target, guarded)
        self._provisioned_targets.add(team_id)

    def _seed_checker_documents(
        self,
        target: VulboxTarget,
        accounts: tuple[tuple[str, str], ...],
    ) -> None:
        base = f"http://{resolve_host(target.host)}:{target.ports['service']}"
        team_id = self._team_id(target)
        clients = []
        for account in accounts:
            client = NextcloudClient(base, *account)
            if not client.login(max_bytes=CHECKER_LOGIN_LIMIT):
                raise RuntimeError("guarded checker identity rejected")
            clients.append(client)
        for _attempt in range(2 * CHECKER_HISTORY_MAX):
            queue, _covers = _reconciled_state(team_id, clients)
            if len(queue) == CHECKER_HISTORY_MAX:
                return
            if len(queue) > CHECKER_HISTORY_MAX:
                raise RuntimeError("guarded checker pair queue exceeds its bound")
            _put_checker_pair(
                clients, checker_pair_successor(team_id, queue[-1][1]))
        raise RuntimeError("guarded checker document seed did not converge")

    def plant(self, target: VulboxTarget,
              flags: Mapping[str, Flag]) -> Mapping[str, str]:
        expected = {STORE_GUARDED_FILE, STORE_COMMAND}
        if set(flags) != expected:
            raise ValueError(f"expected stores {sorted(expected)}, got {sorted(flags)}")
        command_value = flags[STORE_COMMAND].value
        read_value = flags[STORE_GUARDED_FILE].value
        seed = target.meta.get("round_context_seed", "")
        context = _round_context(seed)
        read_target = str(context["target"])
        owner = int(context["owner"])
        cover_after = bool(context["cover_after"])
        cover_target = str(context["cover"])
        cover_body = objective_cover_body(cover_target)

        command_handle, command = self._handle(
            target,
            STORE_COMMAND,
            command_value,
            str(context["operation"]),
            str(context["command_cache"]),
        )
        read_handle, read = self._handle(
            target,
            STORE_GUARDED_FILE,
            read_value,
            read_target,
            str(context["read_cache"]),
            {
                "owner": owner,
                "cover_after": cover_after,
                "cover": cover_target,
            },
        )
        requested: dict[str, object] = {
            "group": context["group"],
            "target": read["target"],
            "cover": cover_target,
            "owner": owner,
            "cover_after": cover_after,
            "operation": command["target"],
            "read_digest": _group_digest(
                seed, STORE_GUARDED_FILE, read_value),
            "command_digest": _group_digest(
                seed, STORE_COMMAND, command_value),
            "read_cache": context["read_cache"],
            "command_cache": context["command_cache"],
        }
        state = self._group_state(target)
        allowed = {
            str(group[key])
            for group in state.values() if group is not None
            for key in ("read_cache", "command_cache")
        } | {str(context["read_cache"]), str(context["command_cache"])}
        self._prune_caches(target, allowed)
        state = self._resume_group(target, state, seed)

        if state["current"] == requested:
            self._converge_group(
                target, read, read_value, cover_body, command, command_value)
            return {
                STORE_COMMAND: command_handle,
                STORE_GUARDED_FILE: read_handle,
            }

        if state["previous"] is not None:
            self._begin_retirement(target, state["previous"])
            self._finish_retirement(target, state["previous"])
            state = self._group_state(target)
        if state["pending"] is not None or state["retiring"] is not None:
            raise RuntimeError("objective group did not converge")

        self._record_pending(target, requested, state["current"])
        self._converge_group(
            target, read, read_value, cover_body, command, command_value)
        self._promote_pending(target, requested)
        state = self._group_state(target)
        if state["current"] != requested or state["pending"] is not None:
            raise RuntimeError("objective-group promotion did not converge")
        return {
            STORE_COMMAND: command_handle,
            STORE_GUARDED_FILE: read_handle,
        }

    def _cached(self, target: VulboxTarget, store: str,
                value: str, target_id: str, cache_key: str,
                extra: Mapping[str, object] | None = None,
                ) -> tuple[str, dict] | None:
        cached = self._cached_by_key(target, cache_key)
        if cached is None:
            return None
        handle, payload = cached
        expected = {
            "store": store,
            "target": target_id,
            "flag": value,
            **dict(extra or {}),
        }
        valid_target = (
            valid_operation(target_id) if store == STORE_COMMAND
            else valid_read_target(target_id)
        )
        if payload != expected or not valid_target:
            raise RuntimeError(f"{store} cached identity is irreconstructible")
        if store == STORE_GUARDED_FILE:
            try:
                _guarded_owner(payload)
                _guarded_cover_after(payload)
                _guarded_cover(payload, target_id)
            except ValueError as error:
                raise RuntimeError(
                    f"{store} cached identity is irreconstructible") from error
        return handle, payload

    def _cached_by_key(
        self, target: VulboxTarget, key: str,
    ) -> tuple[str, dict] | None:
        if re.fullmatch(r"[0-9a-f]{64}", key) is None:
            raise RuntimeError("plant-state cache identity is invalid")
        rc, out = self._exec(target, (
            f"if [ ! -e {CACHE_DIR}/{key} ]; then exit 44; fi; "
            f"test -s {CACHE_DIR}/{key} || exit 45; cat {CACHE_DIR}/{key}"
        ))
        if rc == 44:
            return None
        if rc != 0:
            raise RuntimeError("plant-state integrity failure")
        handle = (out or "").strip()
        payload = unpack_handle(handle)
        if payload is None:
            raise RuntimeError("cached identity is irreconstructible")
        return handle, payload

    def _cache(self, target: VulboxTarget, store: str, cache_key: str,
               handle: str) -> None:
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
        extra: Mapping[str, object] | None = None,
    ) -> tuple[str, dict]:
        cached = self._cached(
            target, store, value, target_id, cache_key, extra)
        if cached:
            return cached
        payload = {
            "store": store,
            "target": target_id,
            "flag": value,
            **dict(extra or {}),
        }
        handle = pack_handle(payload)
        self._cache(target, store, cache_key, handle)
        return handle, payload

    def _publish_command(
        self, target: VulboxTarget, operation: str, value: str,
    ) -> None:
        if not valid_operation(operation):
            raise RuntimeError("invalid command operation id")
        path = f"{OBJECTIVE_DIR}/{operation}"
        encoded = _b64(f"{operation}\n{value}\n")
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
        self, target: VulboxTarget, operation: str,
    ) -> str | None:
        if not valid_operation(operation):
            raise RuntimeError("invalid command operation id")
        path = f"{OBJECTIVE_DIR}/{operation}"
        rc, out = self._exec(target, (
            f"if [ ! -e {path} ]; then exit 44; fi; "
            f"test -f {path} && test -s {path} || exit 45; cat {path}"
        ))
        if rc == 44:
            return None
        lines = (out or "").splitlines() if rc == 0 else []
        if (rc != 0 or len(lines) != 2 or lines[0] != operation
                or not lines[1]):
            raise RuntimeError("command objective state integrity failure")
        return lines[1]

    def _converge_read(
        self, target: VulboxTarget, payload: Mapping[str, object],
        value: str, cover_body: bytes,
    ) -> None:
        self._ensure_guarded_principals(target)
        read_target = str(payload["target"])
        cover_target = str(payload["cover"])
        owner = _guarded_owner(dict(payload))
        cover_after = _guarded_cover_after(dict(payload))
        team_id = self._team_id(target)
        if (team_id not in self._stub_guarded_accounts
                and checker_document_owner(team_id, read_target) is not None):
            raise RuntimeError("guarded target identity conflicts with checker data")
        client = self._guarded_client(target, owner)
        pair = [
            (read_target, value.encode()),
            (cover_target, cover_body),
        ]
        if not cover_after:
            pair.reverse()
        for pair_target, pair_body in pair:
            status, _ = client.webdav("PUT", pair_target, pair_body)
            if status not in (201, 204):
                raise RuntimeError("guarded-file placement failed")
        for pair_target, expected in (
            (read_target, value.encode()),
            (cover_target, cover_body),
        ):
            status, actual = client.webdav("GET", pair_target)
            if status != 200 or actual != expected:
                raise RuntimeError("guarded-file convergence failed")

    def _converge_group(
        self, target: VulboxTarget, read: Mapping[str, object],
        read_value: str, cover_body: bytes, command: Mapping[str, object],
        command_value: str,
    ) -> None:
        self._converge_read(target, read, read_value, cover_body)
        operation = str(command["target"])
        if self._command_generation(target, operation) != command_value:
            self._publish_command(target, operation, command_value)

    def _group_state(
        self, target: VulboxTarget,
    ) -> dict[str, dict[str, object] | None]:
        rc, out = self._exec(target, "/arena/facility.py read-group-state")
        try:
            state = json.loads((out or "").strip()) if rc == 0 else None
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "objective-group target-state integrity failure") from error
        groups = list(state.values()) if isinstance(state, dict) else []
        if (not isinstance(state, dict)
                or set(state) != {"current", "previous", "pending", "retiring"}
                or any(group is not None and not self._valid_group(target, group)
                       for group in groups)
                or (state["pending"] is not None
                    and (state["previous"] is not None
                         or state["retiring"] is not None))
                or (state["retiring"] is not None
                    and (state["previous"] is not None
                         or state["pending"] is not None))
                or (state["current"] is None
                    and (state["previous"] is not None
                         or state["retiring"] is not None))):
            raise RuntimeError("objective-group target-state integrity failure")
        concrete = [group for group in groups if group is not None]
        for keys in (
            ("group",), ("target",), ("cover",), ("operation",),
            ("read_cache", "command_cache"),
        ):
            values = [group[key] for group in concrete for key in keys]
            if len(values) != len(set(values)):
                raise RuntimeError("objective-group target-state integrity failure")
        return state

    def _valid_group(self, target: VulboxTarget, value: object) -> bool:
        if (not isinstance(value, dict) or set(value) != set(_GROUP_FIELDS)
                or not isinstance(value.get("group"), str)
                or re.fullmatch(r"[0-9a-f]{64}", value["group"]) is None
                or not valid_read_target(value.get("target"))
                or not valid_read_target(value.get("cover"))
                or value["target"] == value["cover"]
                or not valid_operation(value.get("operation"))
                or isinstance(value.get("owner"), bool)
                or not isinstance(value.get("owner"), int)
                or not 0 <= value["owner"] < CHECKER_PRINCIPAL_COUNT
                or not isinstance(value.get("cover_after"), bool)):
            return False
        for key in ("read_digest", "command_digest", "read_cache", "command_cache"):
            if (not isinstance(value.get(key), str)
                    or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None):
                return False
        return True

    def _record_pending(
        self, target: VulboxTarget, group: dict[str, object],
        current: dict[str, object] | None,
    ) -> None:
        rc, _ = self._exec(
            target,
            f"/arena/facility.py record-pending {_group_arg(group)} "
            f"{_group_arg(current)}",
        )
        if rc != 0:
            raise RuntimeError("objective-group journal persistence failed")

    def _promote_pending(
        self, target: VulboxTarget, group: dict[str, object],
    ) -> None:
        rc, _ = self._exec(
            target, f"/arena/facility.py promote-pending {_group_arg(group)}")
        if rc != 0:
            raise RuntimeError("objective-group journal promotion failed")

    def _begin_retirement(
        self, target: VulboxTarget, group: dict[str, object],
    ) -> None:
        rc, _ = self._exec(
            target, f"/arena/facility.py begin-retirement {_group_arg(group)}")
        if rc != 0:
            raise RuntimeError("objective-group retirement did not begin")

    def _finish_retirement(
        self, target: VulboxTarget, group: dict[str, object],
    ) -> None:
        owner = int(group["owner"])
        client = self._guarded_client(target, owner)
        retired = [str(group["target"]), str(group["cover"])]
        if bool(group["cover_after"]):
            retired.reverse()
        for retired_target in retired:
            status, _ = client.webdav("DELETE", retired_target)
            if status not in (204, 404):
                raise RuntimeError("guarded-file retirement failed")
        rc, _ = self._exec(
            target, f"/arena/facility.py finish-retirement {_group_arg(group)}")
        if rc != 0:
            raise RuntimeError("objective-group retirement did not converge")

    def _cached_group(
        self, target: VulboxTarget, group: dict[str, object], store: str,
        seed: str,
    ) -> tuple[str, dict]:
        if store == STORE_GUARDED_FILE:
            target_key, digest_key, cache_key = (
                "target", "read_digest", "read_cache")
            extra = {
                "owner": group["owner"],
                "cover_after": group["cover_after"],
                "cover": group["cover"],
            }
        else:
            target_key, digest_key, cache_key = (
                "operation", "command_digest", "command_cache")
            extra = None
        cached = self._cached_by_key(target, str(group[cache_key]))
        if cached is None:
            raise RuntimeError("pending objective group cache is unavailable")
        handle, payload = cached
        value = payload.get("flag")
        if (not isinstance(value, str) or not value
                or not hmac.compare_digest(
                    _group_digest(seed, store, value), str(group[digest_key]))):
            raise RuntimeError("pending objective group cache is invalid")
        validated = self._cached(
            target, store, value, str(group[target_key]),
            str(group[cache_key]), extra)
        if validated is None:
            raise RuntimeError("pending objective group cache is unavailable")
        return handle, payload

    def _resume_group(
        self, target: VulboxTarget,
        state: dict[str, dict[str, object] | None],
        seed: str,
    ) -> dict[str, dict[str, object] | None]:
        if state["retiring"] is not None:
            self._finish_retirement(target, state["retiring"])
            state = self._group_state(target)
        pending = state["pending"]
        if pending is not None:
            _command_handle, command = self._cached_group(
                target, pending, STORE_COMMAND, seed)
            _read_handle, read = self._cached_group(
                target, pending, STORE_GUARDED_FILE, seed)
            read_value = str(read["flag"])
            cover_body = objective_cover_body(str(read["cover"]))
            self._converge_group(
                target, read, read_value, cover_body, command,
                str(command["flag"]))
            self._promote_pending(target, pending)
            state = self._group_state(target)
        return state

    def _prune_caches(self, target: VulboxTarget, allowed: set[str]) -> None:
        if (len(allowed) > 10
                or any(re.fullmatch(r"[0-9a-f]{64}", key) is None
                       for key in allowed)):
            raise RuntimeError("plant-state cache bound is invalid")
        rc, _ = self._exec(
            target,
            "/arena/facility.py prune-caches "
            + _b64(json.dumps(sorted(allowed), separators=(",", ":"))),
        )
        if rc != 0:
            raise RuntimeError("plant-state cache pruning failed")

    def _guarded_client(
        self, target: VulboxTarget, owner: int = 0,
    ) -> NextcloudClient:
        if not 0 <= owner < CHECKER_PRINCIPAL_COUNT:
            raise RuntimeError("guarded application identity unavailable")
        team_id = self._team_id(target)
        accounts = self._stub_guarded_accounts.get(team_id)
        if accounts is None:
            accounts = guarded_principals(team_id)
        account = accounts[owner]
        base = f"http://{resolve_host(target.host)}:{target.ports['service']}"
        client = NextcloudClient(base, *account)
        if not client.login():
            raise RuntimeError("guarded application identity rejected")
        return client

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        payload = unpack_handle(handle)
        if payload is None:
            return FlagObservation(ObservationStatus.ERROR, detail="unreadable handle")
        wanted = expected if expected is not None else payload.get("flag")
        target_id = payload.get("target")
        if payload.get("store") == STORE_COMMAND:
            if not valid_operation(target_id):
                return FlagObservation(ObservationStatus.ERROR,
                                       detail="invalid operation id")
            return exec_read_observe(target, objective_command(target_id), wanted)
        if payload.get("store") != STORE_GUARDED_FILE or not valid_read_target(target_id):
            return FlagObservation(ObservationStatus.ERROR, detail="unknown store")
        try:
            owner = _guarded_owner(payload)
            status, actual = self._guarded_client(
                target, owner).webdav("GET", target_id)
        except Exception as error:  # noqa: BLE001
            return FlagObservation(ObservationStatus.ERROR, detail=str(error))
        if status == 404:
            return FlagObservation(ObservationStatus.NOT_FOUND)
        if status in (401, 403):
            return FlagObservation(ObservationStatus.AUTH_REJECTED,
                                   detail="guarded identity rejected")
        if status != 200:
            return FlagObservation(ObservationStatus.ERROR,
                                   detail=f"guarded read status={status}")
        actual_text = actual.decode(errors="replace")
        if actual_text == wanted:
            return FlagObservation(ObservationStatus.PRESENT, value=actual_text)
        return FlagObservation(ObservationStatus.MISMATCH)

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
