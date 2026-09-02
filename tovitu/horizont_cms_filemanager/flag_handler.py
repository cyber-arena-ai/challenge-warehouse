"""Baseline Editor provisioning and rotating command-execution proof."""

from __future__ import annotations

import base64
import hashlib
import re
import shlex
from collections.abc import Mapping

from challenges.interface import (
    BaselinePrincipal,
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
    exec_read_observe,
)

from ._checker_identity import checker_identities
from ._client import ensure_editor, file_manager


ADMIN_USERNAME = "arena_admin"
ADMIN_PASSWORD_PATH = "/var/lib/horizont/admin-password"
PROOF_DIR = "/var/lib/horizont/proofs"
PROOF_HELPER = "/usr/local/bin/horizont-proof"
_LOCATOR_RE = re.compile(r"[a-f0-9]{24}")


def _identity(seed: str) -> tuple[str, str]:
    username = "arena_" + hashlib.sha256(("user:" + seed).encode()).hexdigest()[:16]
    password = "Hz9!" + hashlib.sha256(("password:" + seed).encode()).hexdigest()[:28]
    return username, password


class HorizontCmsExecuteFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "horizont-cms-filemanager-execute-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, value: str) -> str:
        locator = hashlib.sha256(("horizont-execute:" + value).encode()).hexdigest()[:24]
        encoded = base64.b64encode(value.encode()).decode()
        command = (
            f"install -d -o root -g root -m 0700 {PROOF_DIR} && "
            f"find {PROOF_DIR} -mindepth 1 -maxdepth 1 -type f -delete && "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {PROOF_DIR}/{locator} && "
            f"chown root:root {PROOF_DIR}/{locator} && chmod 0400 {PROOF_DIR}/{locator}"
        )
        rc, _ = target.meta["exec_in_container"](target.host, command)
        if rc != 0:
            raise RuntimeError("HorizontCMS execution-proof plant failed")
        return locator

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        if not _LOCATOR_RE.fullmatch(handle):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid locator")
        return exec_read_observe(
            target,
            f"runuser -u www-data -- {PROOF_HELPER} {handle}",
            expected,
        )

    def flag_id(self, handle: str) -> str | None:
        if not _LOCATOR_RE.fullmatch(handle):
            return None
        return f"{PROOF_HELPER} {handle}"

    def _admin_password(self, target: VulboxTarget) -> str:
        rc, output = target.meta["exec_in_container"](
            target.host, f"cat {ADMIN_PASSWORD_PATH}"
        )
        password = (output or "").strip()
        if rc != 0 or not password:
            raise RuntimeError("HorizontCMS bootstrap administrator is unavailable")
        return password

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        base_url = f"http://{target.host}:{target.ports['service']}"
        admin_password = self._admin_password(target)
        team_id = str(target.meta.get("team_id", ""))
        assignments: list[tuple[str, str, str | None]] = [
            (username, password, None)
            for username, password in checker_identities(team_id)
        ]
        assignments.extend(
            (*_identity(seed), attacker) for attacker, seed in seeds.items()
        )
        issued: dict[str, BaselinePrincipal] = {}
        for username, password, attacker in sorted(assignments):
            session = ensure_editor(
                base_url,
                ADMIN_USERNAME,
                admin_password,
                username,
                password,
                "Arena Editor",
            )
            if attacker is None:
                continue
            file_manager(session)
            issued[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        return issued
