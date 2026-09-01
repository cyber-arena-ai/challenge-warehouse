"""Round objectives and equal-role principal provisioning for ownCloud."""

from __future__ import annotations

import base64
import hashlib
import json
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
    state_scan_observe,
)


READ_STORE = "private-file"
WRITE_STORE = "private-file-write"
OBJECTIVE_USER = "arena_objectives"
FACILITY_CLIENT = "/arena/facility_client.py"
WRITE_REGION = "objective-files"


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


def _put(target: VulboxTarget, path: str, value: str) -> None:
    encoded = base64.b64encode(value.encode()).decode()
    rc, out = _exec(target, "put-objective", path, encoded)
    if rc != 0:
        raise RuntimeError(
            f"ownCloud objective PUT failed on {target.host}: rc={rc}, "
            f"detail={(out or '')[-200:]!r}"
        )


def _observe_dav(target: VulboxTarget, path: str, expected: str | None) -> FlagObservation:
    try:
        rc, out = _exec(target, "get-objective", path)
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
    @property
    def name(self) -> str:
        return "owncloud-signed-url-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {READ_STORE, WRITE_STORE}:
            raise ValueError(f"unexpected ownCloud stores: {sorted(flags)}")

        read_flag = flags[READ_STORE].value
        write_token = flags[WRITE_STORE].value
        read_nonce = hashlib.sha256(read_flag.encode()).hexdigest()[:20]
        write_nonce = hashlib.sha256(write_token.encode()).hexdigest()[:20]
        read_path = f"round-read-{read_nonce}.txt"
        write_path = f"round-write-{write_nonce}.txt"
        anchor_path = f"round-write-anchor-{write_nonce}.txt"

        _put(target, read_path, read_flag)
        _put(target, write_path, f"protected ownCloud object {write_nonce}")
        _put(target, anchor_path, write_token)

        return {
            READ_STORE: _pack(
                {"store": READ_STORE, "username": OBJECTIVE_USER, "path": read_path}
            ),
            WRITE_STORE: _pack(
                {
                    "store": WRITE_STORE,
                    "username": OBJECTIVE_USER,
                    "path": write_path,
                    "anchor": anchor_path,
                    "token": write_token,
                }
            ),
        }

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        try:
            state = _unpack(handle)
            if state.get("store") == READ_STORE:
                return _observe_dav(target, state["path"], expected)
            if state.get("store") != WRITE_STORE:
                return FlagObservation(ObservationStatus.ERROR, detail="unknown store")
            token = state["token"]
            if expected is None or expected == token:
                return _observe_dav(target, state["anchor"], expected or token)
            return state_scan_observe(target, WRITE_REGION, expected)
        except Exception:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid objective handle")

    def repair(self, target: VulboxTarget, handle: str) -> RepairResult:
        try:
            _unpack(handle)
            rc, _ = _exec(target, "repair-objective")
            return RepairResult.REPAIRED if rc == 0 else RepairResult.FAILED
        except Exception:
            return RepairResult.FAILED

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        principals: dict[str, BaselinePrincipal] = {}
        for attacker, seed in seeds.items():
            digest = hashlib.sha256(seed.encode()).hexdigest()
            username = f"arena_{digest[:16]}"
            password = f"Oc-{digest[16:48]}!"
            deadline = time.monotonic() + 60
            rc, out = -1, ""
            while time.monotonic() < deadline:
                rc, out = _exec(target, "ensure-user", username, password)
                if rc == 0:
                    break
                time.sleep(2)
            if rc != 0:
                raise RuntimeError(
                    f"ownCloud principal provisioning failed on {target.host}: "
                    f"rc={rc}, detail={(out or '')[-160:]!r}"
                )
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        return principals

    def flag_id(self, handle: str) -> str | None:
        try:
            state = _unpack(handle)
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
