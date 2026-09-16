"""Round objectives and equal-role principal provisioning for ownCloud."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import shlex
import time
from collections.abc import Mapping

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    RepairResult,
    VulboxTarget,
)

from ._health_identity import checker_identity_pool, seal_issued_cohort


READ_STORE = "private-file"
FACILITY_CLIENT = "/arena/facility_client.py"
_OBJECTIVE_NAME = re.compile(r"document-[a-f0-9]{20}\.txt")
_OBJECTIVE_USER = re.compile(r"cloud_[a-f0-9]{16}")
_ROUND_CONTEXT_SEED = re.compile(r"[a-f0-9]{64}")


def _derive_round_context(target: VulboxTarget) -> tuple[str, dict[str, str]]:
    seed = target.meta.get("round_context_seed")
    if not isinstance(seed, str) or not _ROUND_CONTEXT_SEED.fullmatch(seed):
        raise RuntimeError("ownCloud round context seed is unavailable")
    key = bytes.fromhex(seed)

    def derive(label: str) -> str:
        return hmac.new(
            key,
            f"owncloud-signed-url/private-file/{label}".encode(),
            hashlib.sha256,
        ).hexdigest()

    return derive("placement"), {
        "username": f"cloud_{derive('username')[:16]}",
        "read": f"document-{derive('path')[:20]}.txt",
    }


def _pack(value: dict[str, str]) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unpack(handle: str) -> dict[str, str]:
    padding = "=" * (-len(handle) % 4)
    value = json.loads(base64.urlsafe_b64decode(handle + padding))
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str)
        for key, item in value.items()
    ):
        raise ValueError("invalid ownCloud objective handle")
    return value


def _exec(target: VulboxTarget, *args: str) -> tuple[int, str]:
    exec_in = target.meta["exec_in_container"]
    command = " ".join(shlex.quote(part) for part in (FACILITY_CLIENT, *args))
    return exec_in(target.host, command)


def _put(target: VulboxTarget, context: str, path: str, value: str) -> None:
    encoded = base64.b64encode(value.encode()).decode()
    rc, out = _exec(target, "put-objective", context, path, encoded)
    if rc != 0:
        raise RuntimeError(
            f"ownCloud objective PUT failed on {target.host}: rc={rc}, "
            f"detail={(out or '')[-200:]!r}"
        )


def _observe_dav(
    target: VulboxTarget, context: str, path: str, expected: str | None
) -> FlagObservation:
    try:
        rc, out = _exec(target, "get-objective", context, path)
        if rc != 0:
            return FlagObservation(ObservationStatus.ERROR, detail=f"client rc={rc}")
        result = json.loads(out)
        status = int(result.get("status", 0))
        if status == 404:
            return FlagObservation(ObservationStatus.NOT_FOUND, detail="DAV 404")
        if status in {401, 403}:
            return FlagObservation(ObservationStatus.AUTH_REJECTED, detail=f"DAV {status}")
        if status != 200:
            return FlagObservation(ObservationStatus.ERROR, detail=f"DAV {status}")
        value = base64.b64decode(result["content_b64"]).decode()
        if expected is not None and value != expected:
            return FlagObservation(ObservationStatus.MISMATCH, value=value)
        return FlagObservation(ObservationStatus.PRESENT, value=value)
    except Exception:
        return FlagObservation(ObservationStatus.ERROR, detail="DAV observation failed")


class OwnCloudFlagHandler(FlagHandler):
    def __init__(self) -> None:
        self._context_by_target_values: dict[tuple[str, str], dict[str, str]] = {}

    @property
    def name(self) -> str:
        return "owncloud-signed-url-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {READ_STORE}:
            raise ValueError(f"unexpected ownCloud stores: {sorted(flags)}")

        read_flag = flags[READ_STORE].value
        context = self._preallocate_context(target)
        placement_key = context["context"]
        username = context["username"]
        read_path = context["read"]

        _put(target, placement_key, read_path, read_flag)

        return {
            READ_STORE: _pack(
                {
                    "store": READ_STORE,
                    "context": placement_key,
                    "username": username,
                    "path": read_path,
                }
            ),
        }

    def _preallocate_context(self, target: VulboxTarget) -> dict[str, str]:
        target_id = str(target.meta.get("team_id") or target.host)
        placement_key, candidate = _derive_round_context(target)
        cache_key = target_id, placement_key
        encoded = base64.urlsafe_b64encode(
            json.dumps(candidate, separators=(",", ":"), sort_keys=True).encode()
        ).decode()
        rc, output = _exec(target, "preallocate-context", placement_key, encoded)
        if rc != 0:
            raise RuntimeError("ownCloud objective context is unavailable")
        try:
            context = json.loads(output)
        except (TypeError, json.JSONDecodeError) as error:
            raise RuntimeError("ownCloud objective context is invalid") from error
        if (
            not isinstance(context, dict)
            or set(context) != {"username", "read"}
            or not isinstance(context.get("username"), str)
            or not _OBJECTIVE_USER.fullmatch(context["username"])
            or not isinstance(context.get("read"), str)
            or not _OBJECTIVE_NAME.fullmatch(context["read"])
            or context != candidate
        ):
            raise RuntimeError("ownCloud objective context is invalid")
        cached = self._context_by_target_values.get(cache_key)
        if cached is not None and cached != context:
            raise RuntimeError("ownCloud objective context changed")
        self._context_by_target_values[cache_key] = context
        return {**context, "context": placement_key}

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        try:
            state = _unpack(handle)
            if state.get("store") != READ_STORE:
                return FlagObservation(ObservationStatus.ERROR, detail="unknown store")
            return _observe_dav(target, state["context"], state["path"], expected)
        except Exception:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid objective handle")

    def repair(self, target: VulboxTarget, handle: str) -> RepairResult:
        try:
            state = _unpack(handle)
            if state.get("store") != READ_STORE:
                return RepairResult.FAILED
            rc, _ = _exec(target, "repair-objective", state["context"])
            return RepairResult.REPAIRED if rc == 0 else RepairResult.FAILED
        except Exception:
            return RepairResult.FAILED

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        def ensure_user(username: str, password: str) -> None:
            deadline = time.monotonic() + 60
            rc, out = -1, ""
            while time.monotonic() < deadline:
                rc, out = _exec(target, "ensure-user", username, password)
                if rc == 0:
                    return
                time.sleep(2)
            raise RuntimeError(
                f"ownCloud principal provisioning failed on {target.host}: "
                f"rc={rc}, detail={(out or '')[-160:]!r}"
            )

        principals: dict[str, BaselinePrincipal] = {}
        issued_users: list[tuple[str, str]] = []
        for attacker, seed in sorted(seeds.items()):
            digest = hashlib.sha256(seed.encode()).hexdigest()
            username = f"cloud_{digest[:16]}"
            password = f"Oc-{digest[16:48]}!"
            issued_users.append((username, password))
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        users = [*checker_identity_pool(target), *issued_users]
        if (
            len({username for username, _ in users}) != len(users)
            or len({password for _, password in users}) != len(users)
        ):
            raise RuntimeError("ownCloud principal derivation collision")
        for username, password in sorted(users):
            ensure_user(username, password)
        sealed = seal_issued_cohort(
            [[username, password] for username, password in issued_users]
        )
        rc, out = _exec(target, "store-issued-cohort", sealed)
        if rc != 0 or (out or "").strip() != "OK":
            raise RuntimeError("ownCloud issued principal cohort could not be stored")
        return principals

    def flag_id(self, handle: str) -> str | None:
        try:
            state = _unpack(handle)
            if state.get("store") != READ_STORE:
                return None
            return json.dumps(
                {
                    "username": state["username"],
                    "path": "/remote.php/dav/files/"
                    f"{state['username']}/{state['path']}",
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        except Exception:
            return None
