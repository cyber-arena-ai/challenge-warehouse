"""WRITE oracle and match-long Client provisioning for ProjectSend."""

from __future__ import annotations

import json
import hashlib
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
    state_scan_observe,
)

from ._client import (
    admin_set_title,
    ensure_client,
    ensure_system_user,
    login,
    public_title,
)
from .challenge import OPTIONS_REGION
from .checker_identity import checker_identities


STORE = "global_setting"
PUBLIC_TARGET = "this_install_title"
ADMIN_USER = "arenaadmin"
ADMIN_SECRET_PATH = "/arena/private/admin-password"
STATE_DIR = "/var/lib/cyberarena/projectsend-write"
ANCHOR = f"{STATE_DIR}/integrity"
ROUND_TITLE_PREFIX = "ProjectSend Arena context "


def _admin_password(target: VulboxTarget) -> str:
    exec_in = target.meta["exec_in_container"]
    rc, output = exec_in(target.host, f"cat {ADMIN_SECRET_PATH}")
    if rc != 0 or not output.strip():
        raise RuntimeError("trusted ProjectSend admin credential unavailable")
    return output.strip()


def _base_url(target: VulboxTarget) -> str:
    return f"http://{target.host}:{target.ports['service']}"


def _round_suffix(target: VulboxTarget, token: str) -> str:
    coordinates = f"{target.meta['team_id']}:{token}".encode()
    return hashlib.sha256(coordinates).hexdigest()[:16]


def _unpack(handle: str) -> dict[str, str] | None:
    try:
        state = json.loads(handle)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(state, dict):
        return None
    token = state.get("token")
    target_id = state.get("target_id")
    if not isinstance(token, str) or not token:
        return None
    if not isinstance(target_id, str) or not target_id:
        return None
    return {"token": token, "target_id": target_id}


class ProjectSendSettingsFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "projectsend-global-settings-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected only store {STORE!r}")
        token = flags[STORE].value
        suffix = _round_suffix(target, token)
        base_url = _base_url(target)
        admin = login(base_url, ADMIN_USER, _admin_password(target))
        round_title = ROUND_TITLE_PREFIX + suffix
        admin_set_title(admin, round_title)
        if public_title(base_url) != round_title:
            raise RuntimeError("ProjectSend round context was not persisted")

        exec_in = target.meta["exec_in_container"]
        command = (
            f"install -d -o root -g root -m 700 {STATE_DIR}; "
            f"printf %s {shlex.quote(token)} > {ANCHOR}; "
            f"chown root:root {ANCHOR}; chmod 600 {ANCHOR}"
        )
        rc, _ = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError("ProjectSend integrity-anchor rotation failed")
        target_id = f"{PUBLIC_TARGET}/{suffix}"
        return {STORE: json.dumps({"token": token, "target_id": target_id})}

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        state = _unpack(handle)
        if state is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        if expected == state["token"] or expected is None:
            return exec_read_observe(target, f"cat {ANCHOR}", state["token"])
        return state_scan_observe(target, OPTIONS_REGION, expected)

    def flag_id(self, handle: str) -> str | None:
        state = _unpack(handle)
        return state["target_id"] if state else None

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        base_url = _base_url(target)
        admin = login(base_url, ADMIN_USER, _admin_password(target))
        identities = checker_identities(str(target.meta["team_id"]))
        checker_admin = identities["administrator"]
        checker_client = identities["client"]
        ensure_system_user(
            admin,
            base_url,
            *checker_admin,
            "Arena Health Administrator",
        )
        ensure_client(
            admin,
            base_url,
            *checker_client,
            "Arena Health Client",
        )
        principals: dict[str, BaselinePrincipal] = {}
        for attacker, seed in seeds.items():
            username = "cl" + seed[:14]
            password = "Aa1!" + seed[14:46]
            ensure_client(admin, base_url, username, password, "Arena Client")
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        return principals
