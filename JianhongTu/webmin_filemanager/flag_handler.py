"""Baseline Webmin users and rotating root command-execution proof."""

from __future__ import annotations

import base64
import hashlib
import hmac
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

from ._client import Webmin, ensure_user, login
from .checker_identity import (
    assignment_filename,
    new_checker_identities,
    open_assignments,
    seal_assignments,
)


ADMIN_USERNAME = "arena_admin"
ADMIN_PASSWORD_PATH = "/var/lib/webmin-arena/admin-password"
FILE_MANAGER_ALLOWED_PATH = "/srv/challenge/webmin"
FILE_MANAGER_UNIX_USER = "arena_agent"
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


def _round_locator(round_context_seed: object) -> str:
    if not isinstance(round_context_seed, str) or not re.fullmatch(
        r"[0-9a-f]{64}", round_context_seed
    ):
        raise ValueError("round context seed is unavailable")
    return hmac.new(
        bytes.fromhex(round_context_seed),
        b"webmin-filemanager-execute:default:execute-locator:v1",
        hashlib.sha256,
    ).hexdigest()[:24]


class WebminExecuteFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "webmin-filemanager-execute-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, value: str) -> str:
        locator = _round_locator(target.meta.get("round_context_seed"))
        encoded = base64.b64encode(value.encode()).decode()
        rc, _ = target.meta["exec_in_container"](
            target.host, _broker_set_command(locator, encoded)
        )
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
            f"{BROKER} get {handle}",
            expected,
            read_error_status=ObservationStatus.ERROR,
        )

    def flag_id(self, handle: str) -> str | None:
        if not _LOCATOR_RE.fullmatch(handle):
            return None
        return f"{BROKER} get {handle}"

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
        admin = login(base_url, ADMIN_USERNAME, admin_password)
        team_id = str(target.meta["team_id"])
        issued: dict[str, BaselinePrincipal] = {}
        issued_accounts: list[tuple[str, str]] = []
        users = list(new_checker_identities().values())
        for attacker, seed in seeds.items():
            username, password = _identity(seed)
            users.append((username, password, ("change-user",)))
            issued_accounts.append((username, password))
            issued[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        for username, password, modules in sorted(users):
            ensure_user(
                base_url,
                ADMIN_USERNAME,
                admin_password,
                username,
                password,
                modules,
            )
            admin.set_change_user_acl(username)
            admin.set_file_manager_acl(
                username,
                FILE_MANAGER_ALLOWED_PATH,
                FILE_MANAGER_UNIX_USER,
            )
        context_identity = next(
            (
                identity
                for identity in users
                if identity[2] == ("change-user", "filemin")
            ),
            None,
        )
        if context_identity is None:
            raise RuntimeError("Webmin File Manager facility principal is unavailable")
        context_client = login(base_url, context_identity[0], context_identity[1])
        file_manager_accounts = [
            (username, password)
            for username, password, modules in users
            if modules == ("change-user", "filemin")
        ]
        context = seal_assignments(
            team_id, issued_accounts, file_manager_accounts
        )
        filename = assignment_filename()
        status, _, _ = context_client.file_manager_write(
            filename, FILE_MANAGER_ALLOWED_PATH, context
        )
        chmod_status, _, _ = context_client.file_manager_chmod(
            filename, FILE_MANAGER_ALLOWED_PATH, "0644"
        )
        verify_status, _, persisted = Webmin(base_url).request("GET", "/" + filename)
        try:
            persisted_assignments = open_assignments(team_id, persisted.decode())
        except (UnicodeDecodeError, ValueError) as error:
            raise RuntimeError(
                "Webmin principal assignment record is malformed"
            ) from error
        if (
            status != 302
            or chmod_status != 302
            or verify_status != 200
            or persisted_assignments.issued != tuple(sorted(issued_accounts))
            or persisted_assignments.file_managers
            != tuple(sorted(file_manager_accounts))
        ):
            raise RuntimeError("Webmin principal assignment persistence failed")
        return issued
