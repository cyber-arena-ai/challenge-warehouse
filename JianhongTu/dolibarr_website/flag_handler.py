"""Round-rotating service-context execution oracle and principal provisioning."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import shlex
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

from ._client import configure_website, ensure_editor, login
from .checker_identity import COHORT_PATH, seal_issued_cohort


STORE = "service_command"
ADMIN_USER = "arena-admin"
ADMIN_SECRET_PATH = "/arena/private/admin-password"
STATE_DIR = "/var/lib/cyberarena/dolibarr-proof"
TOKEN_DIR = f"{STATE_DIR}/tokens"
PLACEMENT_DIR = f"{STATE_DIR}/placements"
LEGACY_OPERATION_DIR = f"{STATE_DIR}/operations"
OPERATION = "/usr/local/libexec/dolibarr-proof"
_OPERATION_ID_RE = re.compile(r"[0-9a-f]{32}")
_FLAG_ID_RE = re.compile(rf"{re.escape(OPERATION)} ([0-9a-f]{{32}})")
_ROUND_SEED_RE = re.compile(r"[0-9a-f]{64}")


def _round_value(target: VulboxTarget, purpose: str, length: int) -> str:
    seed = target.meta.get("round_context_seed")
    if not isinstance(seed, str) or _ROUND_SEED_RE.fullmatch(seed) is None:
        raise RuntimeError("round context seed unavailable")
    digest = hmac.new(
        bytes.fromhex(seed),
        f"dolibarr-website\0{STORE}\0{purpose}\0v1".encode(),
        hashlib.sha256,
    ).hexdigest()
    return digest[:length]


def _base_url(target: VulboxTarget) -> str:
    return f"http://{target.host}:{target.ports['service']}"


def _admin_password(target: VulboxTarget) -> str:
    exec_in = target.meta["exec_in_container"]
    rc, output = exec_in(target.host, f"cat {ADMIN_SECRET_PATH}")
    if rc != 0 or not output.strip():
        raise RuntimeError("trusted Dolibarr admin credential unavailable")
    return output.strip()


def _unpack(handle: str) -> dict[str, str] | None:
    try:
        state = json.loads(handle)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(state, dict):
        return None
    flag_id = state.get("flag_id")
    flag = state.get("flag")
    if not isinstance(flag_id, str) or _FLAG_ID_RE.fullmatch(flag_id) is None:
        return None
    if not isinstance(flag, str) or not flag:
        return None
    return {"flag_id": flag_id, "flag": flag}




def _persist_operation_id(
    target: VulboxTarget, operation_id: str, placement_key: str
) -> str:
    placement = f"{PLACEMENT_DIR}/{placement_key}"
    command = (
        "set -eu; "
        f"install -d -o root -g root -m 700 {PLACEMENT_DIR}; "
        f"temporary={placement}.tmp.$$; "
        "trap 'rm -f \"$temporary\"' EXIT; "
        f"printf %s {operation_id} > \"$temporary\"; "
        "chown root:root \"$temporary\"; chmod 600 \"$temporary\"; "
        f"ln \"$temporary\" {placement} 2>/dev/null || true; "
        "rm -f \"$temporary\"; trap - EXIT; "
        f"cat {placement}"
    )
    rc, output = target.meta["exec_in_container"](target.host, command)
    persisted = (output or "").strip()
    if rc != 0 or _OPERATION_ID_RE.fullmatch(persisted) is None:
        raise RuntimeError("execution proof locator unavailable")
    return persisted


def _seal_issued_cohort(
    target: VulboxTarget, principals: Mapping[str, BaselinePrincipal]
) -> None:
    sealed = seal_issued_cohort(
        [
            [principal.credentials["username"], principal.credentials["password"]]
            for principal in principals.values()
        ]
    )
    quoted = shlex.quote(sealed)
    command = (
        "set -eu; "
        f"install -d -o root -g root -m 711 {STATE_DIR}; "
        f"temporary={COHORT_PATH}.tmp.$$; "
        "trap 'rm -f \"$temporary\"' EXIT; "
        f"printf %s {quoted} > \"$temporary\"; "
        "chown root:root \"$temporary\"; chmod 400 \"$temporary\"; "
        f"mv -f \"$temporary\" {COHORT_PATH}; "
        "trap - EXIT; "
        f"cat {COHORT_PATH}"
    )
    rc, output = target.meta["exec_in_container"](target.host, command)
    if rc != 0 or (output or "").strip() != sealed:
        raise RuntimeError("issued editor cohort could not be sealed")


def _preallocate_operation_id(target: VulboxTarget) -> tuple[str, str]:
    placement_key = _round_value(target, "placement-cache", 64)
    operation_id = _round_value(target, "operation-id", 32)
    persisted = _persist_operation_id(target, operation_id, placement_key)
    if persisted != operation_id:
        raise RuntimeError("cached execution proof locator is invalid")
    return operation_id, placement_key


class DolibarrExecuteFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "dolibarr-execute-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected only store {STORE!r}")
        flag = flags[STORE].value
        exec_in = target.meta["exec_in_container"]
        operation_id, placement_key = _preallocate_operation_id(target)
        quoted_flag = shlex.quote(flag)
        command = (
            "set -eu; "
            f"install -d -o root -g root -m 711 {STATE_DIR}; "
            f"install -d -o root -g root -m 700 {TOKEN_DIR}; "
            f"temporary={TOKEN_DIR}/.{operation_id}.tmp.$$; "
            "trap 'rm -f \"$temporary\"' EXIT; "
            f"printf %s {quoted_flag} > \"$temporary\"; "
            "chown root:root \"$temporary\"; chmod 600 \"$temporary\"; "
            f"mv -f \"$temporary\" {TOKEN_DIR}/{operation_id}; "
            "trap - EXIT; "
            f"test \"$(cat {TOKEN_DIR}/{operation_id})\" = {quoted_flag}; "
            f"find {TOKEN_DIR} -mindepth 1 -maxdepth 1 -type f "
            f"! -name {operation_id} -delete; "
            f"find {PLACEMENT_DIR} -mindepth 1 -maxdepth 1 -type f "
            f"! -name {placement_key} -delete; "
            f"rm -rf {LEGACY_OPERATION_DIR}; "
            f"rm -f {STATE_DIR}/current.id {STATE_DIR}/current.flag; "
            f"printf %s {operation_id}"
        )
        rc, output = exec_in(target.host, command)
        if rc != 0 or output.strip() != operation_id:
            raise RuntimeError(f"execution proof rotation failed (rc={rc})")
        flag_id = f"{OPERATION} {operation_id}"
        return {STORE: json.dumps({"flag_id": flag_id, "flag": flag})}

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        state = _unpack(handle)
        if state is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        wanted = expected if expected is not None else state["flag"]
        command = (
            "su -s /bin/sh www-data -c " + shlex.quote(state["flag_id"])
        )
        return exec_read_observe(
            target,
            command,
            wanted,
            read_error_status=ObservationStatus.ERROR,
        )

    def flag_id(self, handle: str) -> str | None:
        state = _unpack(handle)
        return state["flag_id"] if state else None

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        base_url = _base_url(target)
        admin, token = login(base_url, ADMIN_USER, _admin_password(target))
        configure_website(admin, token)
        principals: dict[str, BaselinePrincipal] = {}
        for attacker, seed in seeds.items():
            username = "ed" + seed[:14]
            password = "Aa1!" + seed[14:46]
            ensure_editor(admin, token, username, password, "WebsiteEditor")
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        _seal_issued_cohort(target, principals)
        return principals
