"""Rotating service-context proof and normal-User provisioning."""

from __future__ import annotations

import hashlib
import json
import secrets
import shlex
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

from . import _http
from .config import checker_identity

STORE = "command_execution"
PROOF_PREFIX = "/usr/local/bin/nv-proof-"


class NavigateFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "navigate-cms-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant(self, target: VulboxTarget,
              flags: Mapping[str, Flag]) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected only {STORE!r}")
        target_id = secrets.token_hex(12)
        flag = flags[STORE].value
        exec_in = target.meta["exec_in_container"]
        helper = PROOF_PREFIX + target_id
        token = f"/run/navigate-proof/{target_id}.token"
        cmd = (
            "sh -ceu "
            + shlex.quote(
                "mkdir -p /run/navigate-proof; "
                "rm -f /usr/local/bin/nv-proof-* /run/navigate-proof/*.token; "
                f"printf %s {shlex.quote(flag)} > {shlex.quote(token)}; "
                f"chown root:root {shlex.quote(token)}; chmod 0400 {shlex.quote(token)}; "
                f"cp /usr/local/libexec/navigate-proof {shlex.quote(helper)}; "
                f"chown root:www-data {shlex.quote(helper)}; chmod 4750 {shlex.quote(helper)}"
            )
        )
        rc, _ = exec_in(target.host, cmd)
        if rc != 0:
            raise RuntimeError("Navigate command-execution proof plant failed")
        return {STORE: helper}

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        if not handle.startswith(PROOF_PREFIX) or "/" in handle[len(PROOF_PREFIX):]:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid proof handle")
        if not expected:
            return FlagObservation(ObservationStatus.ERROR, detail="missing expected token")
        try:
            return exec_read_observe(
                target,
                f"runuser -u www-data -- {shlex.quote(handle)}",
                expected,
            )
        except Exception:
            return FlagObservation(ObservationStatus.ERROR, detail="proof execution failed")

    def flag_id(self, handle: str) -> str | None:
        if handle.startswith(PROOF_PREFIX):
            target_id = handle[len(PROOF_PREFIX):]
            if target_id and target_id.isalnum():
                return handle
        return None

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        exec_in = target.meta["exec_in_container"]
        rc, raw = exec_in(target.host, "cat /run/navigate/admin.json")
        if rc != 0:
            raise RuntimeError("Navigate administration bootstrap unavailable")
        try:
            admin = json.loads(raw)
            admin_user = admin["username"]
            admin_password = admin["password"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError("Navigate administration bootstrap invalid") from exc

        base = f"http://{target.host}:{target.ports['service']}/navigate"
        deadline = time.monotonic() + 90
        while True:
            try:
                opener, _ = _http.login(base, admin_user, admin_password)
                break
            except (OSError, RuntimeError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Navigate supported administration unavailable")
                time.sleep(1)

        checker_user, checker_password = checker_identity(
            str(target.meta.get("team_id", ""))
        )
        try:
            _http.create_user(opener, base, checker_user, checker_password)
            _http.login(base, checker_user, checker_password)
        except RuntimeError as exc:
            raise RuntimeError("checker User provisioning failed") from exc

        result: dict[str, BaselinePrincipal] = {}
        for team_id, seed in seeds.items():
            digest = hashlib.sha256(seed.encode()).hexdigest()
            username = "nv_" + digest[:20]
            password = "Nv!" + digest[20:52]
            try:
                _http.create_user(opener, base, username, password)
                _http.login(base, username, password)
            except RuntimeError as exc:
                raise RuntimeError("normal User provisioning failed") from exc
            result[team_id] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        return result
