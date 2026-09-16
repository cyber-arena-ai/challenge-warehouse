"""GeoServer-native principal and READ/EXECUTE objective placement."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
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

from ._client import GeoServerClient, resolve_host
from ._ids import (
    STORE_COMMAND,
    STORE_PROTECTED_FEATURE,
    checker_principals,
    derive_principal,
    feature_category,
    feature_target,
    objective_command,
    pack_handle,
    public_flag_id,
    road_lifecycle_principals,
    seal_issued_cohort,
    unpack_handle,
    valid_operation,
)
from .journal import (
    PHASE_INTENT,
    PHASE_RECHECKED,
    JournalEntry,
    begin_placement_trace,
    complete_placement_trace,
    facility_key,
    finish_placement_trace,
    initialize_journal,
    placement_journal_id,
)
from .image.road_protocol import GEOMETRY_SPAN, GEOMETRY_X, GEOMETRY_Y

OBJECTIVE_DIR = "/opt/arena/objective"
OBJECTIVE_PATH = OBJECTIVE_DIR + "/current"
CACHE_DIR = "/arena/state/plants"
_ROUND_SEED_RE = re.compile(r"[0-9a-f]{64}")
_FEATURE_CATEGORY_COUNT = 64


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


def _round_context(seed: object) -> dict[str, object]:
    """Derive independent, proof-free identities for one round's objectives."""
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise ValueError("round context seed is unavailable")
    key = bytes.fromhex(seed)

    def derive(label: str) -> bytes:
        return hmac.new(
            key,
            f"geoserver-spatial-service\0round-context-v1\0{label}".encode(),
            hashlib.sha256,
        ).digest()

    def number(label: str, bound: int) -> int:
        return int.from_bytes(derive(label), "big") % bound

    categories: list[int] = []
    counter = 0
    while len(categories) < _FEATURE_CATEGORY_COUNT:
        category = 1 + number(
            f"{STORE_PROTECTED_FEATURE}:category:{counter}", 9999
        )
        if category not in categories:
            categories.append(category)
        counter += 1

    span = GEOMETRY_SPAN[0] + number(
        f"{STORE_PROTECTED_FEATURE}:geometry:span",
        GEOMETRY_SPAN[1] - GEOMETRY_SPAN[0] + 1,
    )
    center_x = GEOMETRY_X[0] + span + number(
        f"{STORE_PROTECTED_FEATURE}:geometry:x",
        GEOMETRY_X[1] - GEOMETRY_X[0] - 2 * span + 1,
    )
    center_y = GEOMETRY_Y[0] + span + number(
        f"{STORE_PROTECTED_FEATURE}:geometry:y",
        GEOMETRY_Y[1] - GEOMETRY_Y[0] - 2 * span + 1,
    )
    slope = -1 if number(
        f"{STORE_PROTECTED_FEATURE}:geometry:slope", 2
    ) else 1

    return {
        "command_cache": derive(f"{STORE_COMMAND}:placement-cache").hex(),
        "command_target": derive(f"{STORE_COMMAND}:target").hex()[:32],
        "feature_context": derive(
            f"{STORE_PROTECTED_FEATURE}:identity"
        ).hex(),
        "feature_categories": categories,
        "feature_geometry": [
            [center_x - span, center_y - slope * span],
            [center_x + span, center_y + slope * span],
        ],
    }


class GeoServerFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "geoserver-xpath-flag-handler"

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
        issued_accounts: list[tuple[str, str]] = []
        users: list[dict[str, object]] = []
        for attacker, seed in sorted(seeds.items()):
            username, password = derive_principal(seed)
            issued_accounts.append((username, password))
            users.append({"username": username, "password": password})
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        team_id = str(target.meta.get("team_id") or "")
        for authority in ("ordinary", "guarded"):
            for username, password in checker_principals(team_id, authority):
                users.append({
                    "username": username,
                    "password": password,
                    "guarded": authority == "guarded",
                })
        users.sort(key=lambda user: str(user["username"]))
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

        guarded_username, guarded_password = checker_principals(
            team_id, "guarded"
        )[0]
        host = resolve_host(target.host)
        client = GeoServerClient(
            f"http://{host}:{target.ports['service']}",
            guarded_username,
            guarded_password,
        )
        initialize_journal(client, facility_key(), team_id)
        initialize_journal(
            client, facility_key(), placement_journal_id(team_id)
        )

        sealed = seal_issued_cohort(issued_accounts)
        rc, out = self._exec(
            target, f"/arena/facility.py store-issued-cohort {sealed}"
        )
        if rc != 0 or (out or "").strip() != "OK":
            raise RuntimeError("issued principal cohort could not be stored")

        return principals

    def plant(
        self,
        target: VulboxTarget,
        flags: Mapping[str, Flag],
    ) -> Mapping[str, str]:
        expected = {STORE_PROTECTED_FEATURE, STORE_COMMAND}
        if set(flags) != expected:
            raise ValueError(f"expected stores {sorted(expected)}, got {sorted(flags)}")
        context = _round_context(target.meta.get("round_context_seed"))
        return {
            STORE_COMMAND: self._plant_command(
                target,
                flags[STORE_COMMAND].value,
                str(context["command_cache"]),
                str(context["command_target"]),
            ),
            STORE_PROTECTED_FEATURE: self._plant_feature(
                target, flags[STORE_PROTECTED_FEATURE].value, context
            ),
        }

    def _cached(
        self, target: VulboxTarget, store: str, value: str, key: str,
    ) -> str | None:
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
        if payload and payload.get("store") == store and payload.get("flag") == value:
            return handle
        raise RuntimeError(f"cached {store} plant state is invalid")

    def _cache(
        self,
        target: VulboxTarget,
        store: str,
        key: str,
        handle: str,
    ) -> None:
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

    def _plant_command(
        self, target: VulboxTarget, value: str, cache_key: str, operation: str,
    ) -> str:
        cached = self._cached(target, STORE_COMMAND, value, cache_key)
        if cached:
            payload = unpack_handle(cached) or {}
            cached_operation = payload.get("target")
            if cached_operation != operation or not valid_operation(cached_operation):
                raise RuntimeError("cached command operation id is invalid")
            self._write_command_objective(target, operation, value)
            observed = self.retrieve(target, cached, expected=value)
            if observed.status is not ObservationStatus.PRESENT:
                raise RuntimeError(
                    "command objective could not be restored through its operation"
                )
            return cached
        handle = pack_handle({
            "store": STORE_COMMAND,
            "target": operation,
            "flag": value,
        })
        self._cache(target, STORE_COMMAND, cache_key, handle)
        self._write_command_objective(target, operation, value)
        return handle

    def _write_command_objective(
        self, target: VulboxTarget, operation: str, value: str,
    ) -> None:
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

    def _plant_feature(
        self, target: VulboxTarget, value: str, context: Mapping[str, object],
    ) -> str:
        team_id = str(target.meta.get("team_id") or "")
        if not team_id:
            raise RuntimeError("protected-feature placement context unavailable")
        context_id = str(context["feature_context"])

        def parse_result(raw: str) -> tuple[int, JournalEntry | None]:
            try:
                result = json.loads((raw or "").strip())
                category = int(result["category"])
                nonce = str(result["retire_nonce"])
                born_at = int(result["retire_born_at"])
                feature_target(category, context_id)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise RuntimeError("protected-feature placement failed") from error
            if nonce == "" and born_at == 0:
                return category, None
            return category, JournalEntry(nonce, born_at, PHASE_RECHECKED)

        def public_handle(category: int) -> str:
            return pack_handle({
                "store": STORE_PROTECTED_FEATURE,
                "target": feature_target(category, context_id),
                "flag": value,
            })

        trace_context = None
        creator = ""
        observer = ""
        if "CYBERARENA_FACILITY_TOKEN" in os.environ:
            ordinary_principal, guarded_principal = road_lifecycle_principals(
                team_id
            )
            observer = ordinary_principal[0]
            creator, password = guarded_principal
            client = GeoServerClient(
                f"http://{resolve_host(target.host)}:{target.ports['service']}",
                creator,
                password,
            )
            key = facility_key()
            pending_rc, pending_out = self._exec(
                target, f"/arena/facility.py pending-feature {context_id}"
            )
            if pending_rc not in (0, 44):
                raise RuntimeError("protected-feature trace recovery failed")
            if pending_rc == 0:
                try:
                    pending = json.loads((pending_out or "").strip())
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                    raise RuntimeError(
                        "protected-feature trace recovery failed"
                    ) from error
                if pending.get("complete") is True:
                    try:
                        return public_handle(int(pending["category"]))
                    except (KeyError, TypeError, ValueError) as error:
                        raise RuntimeError(
                            "protected-feature trace recovery failed"
                        ) from error
                try:
                    resume = JournalEntry(
                        str(pending["nonce"]), int(pending["born_at"]),
                        PHASE_INTENT,
                    )
                    same = pending["same"] is True
                except (KeyError, TypeError, ValueError) as error:
                    raise RuntimeError(
                        "protected-feature trace recovery failed"
                    ) from error
                trace = begin_placement_trace(
                    client, key, team_id, int(time.time()), resume=resume
                )
                rc, out = self._exec(
                    target,
                    f"/arena/facility.py resume-feature {creator} {observer}",
                )
                if rc != 0:
                    raise RuntimeError("protected-feature placement failed")
                category, retirement_entry = parse_result(out)
                trace = finish_placement_trace(
                    client, key, team_id, trace, int(time.time()),
                    retirement_entry,
                )
                final_rc, _ = self._exec(
                    target, f"/arena/facility.py finalize-feature {creator}"
                )
                if final_rc != 0:
                    raise RuntimeError("protected-feature retirement failed")
                trace = complete_placement_trace(
                    client, key, team_id, trace, int(time.time()),
                    retirement_entry,
                )
                clear_rc, _ = self._exec(
                    target,
                    f"/arena/facility.py clear-feature {trace.nonce} "
                    f"{trace.born_at}",
                )
                if clear_rc != 0:
                    raise RuntimeError("protected-feature retirement state failed")
                if same:
                    return public_handle(category)

            trace = begin_placement_trace(
                client, key, team_id, int(time.time())
            )
            trace_context = client, key, trace

        request = {
            "context": context_id,
            "value": value,
            "categories": context["feature_categories"],
            "geometry": context["feature_geometry"],
        }
        command = (
            "/arena/facility.py plant-feature "
            + _b64(json.dumps(request, separators=(",", ":")))
        )
        if trace_context is not None:
            command += (
                f" {creator} {observer} {trace.nonce} {trace.born_at}"
            )
        rc, out = self._exec(target, command)
        if rc != 0:
            raise RuntimeError("protected-feature placement failed")
        category, retirement_entry = parse_result(out)
        if trace_context is not None:
            client, key, trace = trace_context
            trace = finish_placement_trace(
                client, key, team_id, trace, int(time.time()), retirement_entry
            )
        finalize = "/arena/facility.py finalize-feature"
        if creator:
            finalize += f" {creator}"
        final_rc, _ = self._exec(target, finalize)
        if final_rc != 0:
            raise RuntimeError("protected-feature retirement failed")
        if trace_context is not None:
            client, key, trace = trace_context
            trace = complete_placement_trace(
                client, key, team_id, trace, int(time.time()), retirement_entry
            )
        clear = "/arena/facility.py clear-feature"
        if trace_context is not None:
            clear += f" {trace.nonce} {trace.born_at}"
        clear_rc, _ = self._exec(target, clear)
        if clear_rc != 0:
            raise RuntimeError("protected-feature retirement state failed")
        return public_handle(category)

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
        category = feature_category(target_id)
        if category is None:
            return FlagObservation(
                ObservationStatus.ERROR, detail="invalid feature locator"
            )
        try:
            command = f"/arena/facility.py read-feature {category}"
            if "CYBERARENA_FACILITY_TOKEN" in os.environ:
                team_id = str(target.meta.get("team_id") or "")
                _ordinary, guarded = road_lifecycle_principals(team_id)
                command += f" {guarded[0]}"
            rc, out = self._exec(target, command)
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
