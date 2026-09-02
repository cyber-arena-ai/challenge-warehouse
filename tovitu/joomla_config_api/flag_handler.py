"""Guarded SMTP credential placement and baseline provisioning."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import time
from collections.abc import Mapping

from challenges.interface import (
    BaselinePrincipal,
    FlagObservation,
    ObservationStatus,
    SingleFlagHandler,
    VulboxTarget,
)

from . import _http
from .checker_identity import checker_identities

HANDLE = "smtp-configuration"


def _read_json(target: VulboxTarget, path: str) -> dict[str, str]:
    exec_in = target.meta["exec_in_container"]
    rc, raw = exec_in(target.host, f"cat {shlex.quote(path)}")
    if rc != 0:
        raise RuntimeError("trusted Joomla credential unavailable")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("trusted Joomla credential invalid")
    return {str(key): str(item) for key, item in value.items()}


class JoomlaFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "joomla-config-api-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, value: str) -> str:
        credentials = _read_json(target, "/run/joomla/facility.json")
        base = f"http://{target.host}:{target.ports['service']}"
        token = _http.admin_token(
            base,
            credentials["username"],
            credentials["password"],
        )
        status, _ = _http.api_request(
            base,
            token,
            method="PATCH",
            payload={
                "mailer": "smtp",
                "smtphost": "mail.arena.invalid",
                "smtpuser": "arena-smtp-user",
                "smtppass": value,
            },
        )
        if status != 200:
            raise RuntimeError("guarded Joomla credential placement failed")
        observed = self.retrieve(target, HANDLE, value)
        if observed.status is not ObservationStatus.PRESENT:
            raise RuntimeError("guarded Joomla credential did not converge")
        return HANDLE

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        if handle != HANDLE:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        try:
            credentials = _read_json(target, "/run/joomla/facility.json")
            base = f"http://{target.host}:{target.ports['service']}"
            token = _http.admin_token(
                base,
                credentials["username"],
                credentials["password"],
            )
            status, raw = _http.api_request(base, token)
            if status in {401, 403}:
                return FlagObservation(
                    ObservationStatus.AUTH_REJECTED,
                    detail="guarded configuration access rejected",
                )
            if status != 200:
                return FlagObservation(
                    ObservationStatus.ERROR, detail=f"configuration HTTP {status}"
                )
            actual = _http.config_values(raw).get("smtppass")
            if not isinstance(actual, str) or not actual:
                return FlagObservation(
                    ObservationStatus.NOT_FOUND, detail="SMTP credential absent"
                )
            if expected is not None and actual != expected:
                return FlagObservation(ObservationStatus.MISMATCH, value=actual)
            return FlagObservation(ObservationStatus.PRESENT, value=actual)
        except _http.AuthenticationError:
            return FlagObservation(
                ObservationStatus.AUTH_REJECTED,
                detail="trusted Joomla administrator rejected",
            )
        except Exception:
            return FlagObservation(
                ObservationStatus.ERROR, detail="guarded configuration read failed"
            )

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        exec_in = target.meta["exec_in_container"]
        base = f"http://{target.host}:{target.ports['service']}"

        def ensure_user(username: str, password: str, group: str) -> None:
            rc, users = exec_in(
                target.host,
                "php /srv/challenge/joomla/cli/joomla.php user:list --no-ansi",
            )
            if rc != 0:
                raise RuntimeError("Joomla user listing failed")
            if re.search(r"^\s*\d+\s+" + re.escape(username) + r"\s", users, re.M):
                return
            email = f"{username}@arena.invalid"
            command = " ".join(
                shlex.quote(part)
                for part in (
                    "php",
                    "/srv/challenge/joomla/cli/joomla.php",
                    "user:add",
                    f"--username={username}",
                    f"--name={username}",
                    f"--password={password}",
                    f"--email={email}",
                    f"--usergroup={group}",
                    "--no-interaction",
                    "--no-ansi",
                )
            )
            rc, _ = exec_in(target.host, command)
            if rc != 0:
                raise RuntimeError(f"Joomla {group} principal creation failed")

        registered_checker, administrator_checker = checker_identities(
            str(target.meta["team_id"])
        )
        ensure_user(*registered_checker, "Registered")
        ensure_user(*administrator_checker, "Super Users")
        _http.frontend_login(base, *registered_checker)
        _http.admin_token(base, *administrator_checker)

        result: dict[str, BaselinePrincipal] = {}
        for team_id, seed in seeds.items():
            digest = hashlib.sha256(seed.encode()).hexdigest()
            username = "arena_" + digest[:18]
            password = "Jm!" + digest[18:58]
            ensure_user(username, password, "Registered")
            deadline = time.monotonic() + 30
            while True:
                try:
                    _http.frontend_login(base, username, password)
                    break
                except (OSError, RuntimeError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Joomla Registered principal login failed")
                    time.sleep(1)
            result[team_id] = BaselinePrincipal(
                principal_id=username,
                credentials={"username": username, "password": password},
            )
        return result
