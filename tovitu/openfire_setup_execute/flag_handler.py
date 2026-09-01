"""Per-attacker XMPP identities and rotating service-execution proofs."""

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

from ._client import ensure_user, login
from .challenge import ADMIN_PASSWORD_PATH


PROOF_DIR = "/var/lib/openfire-arena/proofs"
PROOF_HELPER = "/usr/local/bin/openfire-proof"
_LOCATOR_RE = re.compile(r"[a-f0-9]{24}")


def _identity(seed: str) -> tuple[str, str]:
    username = "arena-" + hashlib.sha256(("xmpp-user:" + seed).encode()).hexdigest()[:16]
    password = "Of9!" + hashlib.sha256(("xmpp-password:" + seed).encode()).hexdigest()[:28]
    return username, password


class OpenfireExecuteFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "openfire-setup-execute-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, value: str) -> str:
        locator = hashlib.sha256(("openfire-execute:" + value).encode()).hexdigest()[:24]
        encoded = base64.b64encode(value.encode()).decode()
        command = (
            f"install -d -o root -g openfire -m 0710 {PROOF_DIR} && "
            f"find {PROOF_DIR} -mindepth 1 -maxdepth 1 -type f -delete && "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {PROOF_DIR}/{locator} && "
            f"chown root:root {PROOF_DIR}/{locator} && chmod 0400 {PROOF_DIR}/{locator}"
        )
        rc, _ = target.meta["exec_in_container"](target.host, command)
        if rc != 0:
            raise RuntimeError("Openfire execution-proof plant failed")
        return locator

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        if not _LOCATOR_RE.fullmatch(handle):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid locator")
        return exec_read_observe(
            target,
            f"runuser -u openfire -- {PROOF_HELPER} {handle}",
            expected,
        )

    def flag_id(self, handle: str) -> str | None:
        return handle if _LOCATOR_RE.fullmatch(handle) else None

    def _admin_password(self, target: VulboxTarget) -> str:
        rc, output = target.meta["exec_in_container"](
            target.host, f"cat {ADMIN_PASSWORD_PATH}"
        )
        password = (output or "").strip()
        if rc != 0 or not password:
            raise RuntimeError("Openfire bootstrap administrator is unavailable")
        return password

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        base_url = f"http://{target.host}:{target.ports['service']}"
        admin = login(base_url, "admin", self._admin_password(target))
        issued: dict[str, BaselinePrincipal] = {}
        for attacker, seed in sorted(seeds.items()):
            username, password = _identity(seed)
            ensure_user(admin, username, password, "Arena XMPP User")
            issued[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        return issued
