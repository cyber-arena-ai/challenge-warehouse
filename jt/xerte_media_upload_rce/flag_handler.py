"""Baseline principals and EXECUTE objective placement for Xerte."""

from __future__ import annotations

import base64
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

from ._client import XerteApi, resolve_host
from ._ids import (
    STORE_COMMAND,
    catflag_command,
    checker_principals,
    derive_principal,
    encode_execute_target,
    objective_operation,
    pack_handle,
    public_flag_id,
    unpack_handle,
)

OBJECTIVE_DIR = "/var/lib/arena/command"
OBJECTIVE_PATH = OBJECTIVE_DIR + "/objective"


class XerteFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "xerte-media-upload-rce-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    # ── facility plumbing ────────────────────────────────────────────────
    def _api(self, target: VulboxTarget) -> XerteApi:
        host = resolve_host(target.host)
        return XerteApi(f"http://{host}:{target.ports['service']}")

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> tuple[int, str]:
        return target.meta["exec_in_container"](target.host, command)

    def _credentials(self, target: VulboxTarget, role: str) -> dict[str, str]:
        rc, out = self._exec(target, f"/arena/facility.sh credentials {role}")
        values = {}
        for line in (out or "").splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and value:
                values[key] = value
        if rc != 0 or not values:
            raise RuntimeError(f"facility {role} credentials unavailable")
        return values

    # ── baseline principals ──────────────────────────────────────────────
    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        """One ordinary Xerte account per attacker, minted once for the match
        through the application's own Db user-management operation."""
        api = self._api(target)
        admin = self._credentials(target, "admin")
        admin_session = api.login(admin["user"], admin["pass"])
        if admin_session is None:
            raise RuntimeError("facility site account rejected")
        team_id = str(target.meta["team_id"])
        assignments: list[tuple[str | None, str, str, str]] = [
            (None, username, password, f"{username}@arena.invalid")
            for username, password in checker_principals(team_id)
        ]
        for attacker, seed in sorted(seeds.items()):
            username, password, email = derive_principal(seed)
            assignments.append((attacker, username, password, email))
        usernames = [row[1] for row in assignments]
        if len(usernames) != len(set(usernames)):
            raise RuntimeError("ordinary principal identity collision")

        granted: dict[str, BaselinePrincipal] = {}
        for attacker, username, password, email in sorted(
            assignments, key=lambda row: row[1]
        ):
            api.add_user(admin_session, username, password,
                         "Course", "Author", email)
            if api.login(username, password) is None:
                raise RuntimeError("baseline principal login rejected")
            if attacker is not None:
                granted[attacker] = BaselinePrincipal(
                    principal_id=username,
                    credentials={"username": username, "password": password},
                )
        return granted

    def plant(self, target: VulboxTarget,
              flags: Mapping[str, Flag]) -> Mapping[str, str]:
        if set(flags) != {STORE_COMMAND}:
            raise ValueError(f"expected store {STORE_COMMAND!r}, got {sorted(flags)}")
        value = flags[STORE_COMMAND].value
        operation_key = self._credentials(target, "objective")["key"]
        operation = objective_operation(
            operation_key, str(target.meta["team_id"]), value)
        # Reconcile the authoritative file on every call. The operation and
        # handle are deterministic for this target and fresh round, so partial
        # state recovers without rotating the public objective.
        payload = base64.b64encode(f"{operation}\n{value}\n".encode()).decode()
        rc, _ = self._exec(target, (
            f"install -d -o root -g root -m 0700 {OBJECTIVE_DIR}; "
            f"printf %s {payload} | base64 -d > {OBJECTIVE_PATH}.new; "
            f"chown root:root {OBJECTIVE_PATH}.new; chmod 0600 {OBJECTIVE_PATH}.new; "
            f"mv -f {OBJECTIVE_PATH}.new {OBJECTIVE_PATH}"))
        if rc != 0:
            raise RuntimeError("command objective placement failed")
        handle = pack_handle({
            "store": STORE_COMMAND,
            "op": operation,
            "target": encode_execute_target(operation=operation),
            "flag": value,
        })
        return {STORE_COMMAND: handle}

    def retrieve(self, target: VulboxTarget, handle: str,
                 expected: str | None = None) -> FlagObservation:
        payload = unpack_handle(handle)
        if payload is None or payload.get("store") != STORE_COMMAND:
            return FlagObservation(ObservationStatus.ERROR, detail="unreadable handle")
        operation = payload.get("op")
        if not isinstance(operation, str) or not operation:
            return FlagObservation(ObservationStatus.ERROR, detail="missing operation id")
        wanted = expected if expected is not None else payload.get("flag")
        # Exercise the helper itself, in the same service execution context an
        # attacker who reached execution would use.
        return exec_read_observe(target, catflag_command(operation), wanted)

    def flag_id(self, handle: str) -> str | None:
        return public_flag_id(handle)
