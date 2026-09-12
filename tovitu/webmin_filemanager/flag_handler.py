"""Baseline Webmin users and rotating root command-execution proof."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
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

from ._client import ensure_restricted_user, ensure_user
from .checker_identity import checker_identities


ADMIN_USERNAME = "arena_admin"
ADMIN_PASSWORD_PATH = "/var/lib/webmin-arena/admin-password"
RELEASE_DIR = "/var/lib/webmin-arena/releases"
BROKER = "/arena/release_broker.pl"
BROKER_SOCKET = "/run/webmin-arena/release.sock"
_LOCATOR_RE = re.compile(r"[a-f0-9]{24}")


def _broker_set_command(locator: str, encoded: str) -> str:
    program = (
        "my $s=IO::Socket::UNIX->new(Type=>SOCK_STREAM,Peer=>$ARGV[0],Timeout=>2) "
        "or exit 2; print $s qq(SET $ARGV[1] $ARGV[2]\\n); "
        "my $r=<$s>//q(); exit($r eq qq(OK\\n) ? 0 : 3)"
    )
    return (
        "/usr/local/bin/perl -MIO::Socket::UNIX -MSocket=SOCK_STREAM -e "
        f"{shlex.quote(program)} {BROKER_SOCKET} {locator} {shlex.quote(encoded)}"
    )


def _identity(seed: str) -> tuple[str, str]:
    username = "arena_" + hashlib.sha256(("user:" + seed).encode()).hexdigest()[:16]
    password = "Wm9!" + hashlib.sha256(("password:" + seed).encode()).hexdigest()[:28]
    return username, password


class WebminExecuteFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "webmin-filemanager-execute-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, value: str) -> str:
        locator = secrets.token_hex(12)
        encoded = base64.b64encode(value.encode()).decode()
        release = f"{RELEASE_DIR}/release-{locator}"
        broker_set = _broker_set_command(locator, encoded)
        command = (
            f"install -d -o root -g root -m 0700 {RELEASE_DIR} && "
            f"find {RELEASE_DIR} -mindepth 1 -maxdepth 1 -type f -delete && "
            f"{broker_set} && "
            f"printf '%s\n' '#!/bin/sh' "
            f"'exec /usr/local/bin/perl {BROKER} get {locator}' > {release} && "
            f"chown root:root {release} && chmod 0500 {release}"
        )
        rc, _ = target.meta["exec_in_container"](target.host, command)
        if rc != 0:
            raise RuntimeError("Webmin execution-proof plant failed")
        return locator

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        if not _LOCATOR_RE.fullmatch(handle):
            return FlagObservation(ObservationStatus.ERROR, detail="invalid locator")
        return exec_read_observe(
            target,
            f"{RELEASE_DIR}/release-{handle}",
            expected,
            read_error_status=ObservationStatus.ERROR,
        )

    def flag_id(self, handle: str) -> str | None:
        if not _LOCATOR_RE.fullmatch(handle):
            return None
        return f"{RELEASE_DIR}/release-{handle}"

    def _admin_password(self, target: VulboxTarget) -> str:
        rc, output = target.meta["exec_in_container"](
            target.host, f"cat {ADMIN_PASSWORD_PATH}"
        )
        password = (output or "").strip()
        if rc != 0 or not password:
            raise RuntimeError("Webmin bootstrap administrator is unavailable")
        return password

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        base_url = f"http://{target.host}:{target.ports['service']}"
        admin_password = self._admin_password(target)
        team_id = str(target.meta["team_id"])
        for username, password, modules in checker_identities(team_id).values():
            ensure_user(
                base_url,
                ADMIN_USERNAME,
                admin_password,
                username,
                password,
                modules,
            )
        issued: dict[str, BaselinePrincipal] = {}
        for attacker, seed in sorted(seeds.items()):
            username, password = _identity(seed)
            ensure_restricted_user(
                base_url,
                ADMIN_USERNAME,
                admin_password,
                username,
                password,
            )
            issued[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        return issued
