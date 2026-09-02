"""Round-rotating service-context execution oracle and principal provisioning."""

from __future__ import annotations

import json
import re
import secrets
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
from .checker_identity import checker_credentials


STORE = "service_command"
ADMIN_USER = "arena-admin"
ADMIN_SECRET_PATH = "/arena/private/admin-password"
STATE_DIR = "/var/lib/cyberarena/dolibarr-proof"
OPERATION_DIR = f"{STATE_DIR}/operations"
TOKEN_DIR = f"{STATE_DIR}/tokens"
TEMPLATE = "/usr/local/libexec/dolibarr-proof-template"
_OPERATION_ID_RE = re.compile(r"[0-9a-f]{32}")


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
    if not isinstance(flag_id, str) or not flag_id.startswith(OPERATION_DIR + "/"):
        return None
    if not isinstance(flag, str) or not flag:
        return None
    return {"flag_id": flag_id, "flag": flag}


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
        quoted_flag = shlex.quote(flag)
        reuse_command = (
            "set -eu; "
            f"if [ -s {STATE_DIR}/current.flag ] && "
            f"[ \"$(cat {STATE_DIR}/current.flag)\" = {quoted_flag} ] && "
            f"[ -s {STATE_DIR}/current.id ]; then "
            f"cat {STATE_DIR}/current.id; "
            "fi"
        )
        rc, output = exec_in(target.host, reuse_command)
        candidate = output.strip()
        operation_id = (
            candidate
            if rc == 0 and _OPERATION_ID_RE.fullmatch(candidate)
            else secrets.token_hex(16)
        )
        command = (
            "set -eu; "
            f"install -d -o root -g root -m 711 {STATE_DIR}; "
            f"install -d -o root -g root -m 700 {TOKEN_DIR}; "
            f"install -d -o root -g root -m 711 {OPERATION_DIR}; "
            f"find {OPERATION_DIR} -mindepth 1 -maxdepth 1 "
            "-exec rm -rf -- {} +; "
            f"find {TOKEN_DIR} -mindepth 1 -maxdepth 1 "
            "-exec rm -rf -- {} +; "
            f"install -o root -g root -m 4755 {TEMPLATE} "
            f"{OPERATION_DIR}/{operation_id}; "
            f"printf %s {quoted_flag} > {TOKEN_DIR}/{operation_id}; "
            f"chown root:root {TOKEN_DIR}/{operation_id}; "
            f"chmod 600 {TOKEN_DIR}/{operation_id}; "
            f"printf %s {operation_id} > {STATE_DIR}/current.id; "
            f"printf %s {quoted_flag} > {STATE_DIR}/current.flag; "
            f"chown root:root {STATE_DIR}/current.id {STATE_DIR}/current.flag; "
            f"chmod 600 {STATE_DIR}/current.id {STATE_DIR}/current.flag; "
            f"printf %s {operation_id}"
        )
        rc, output = exec_in(target.host, command)
        if rc != 0 or output.strip() != operation_id:
            raise RuntimeError(f"execution proof rotation failed (rc={rc})")
        flag_id = f"{OPERATION_DIR}/{operation_id}"
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
        checker_user, checker_password = checker_credentials(target)
        ensure_editor(
            admin,
            token,
            checker_user,
            checker_password,
            "WebsiteEditor",
        )
        return principals
