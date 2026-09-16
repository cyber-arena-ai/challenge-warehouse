"""Rotating execution-release objective and native principal provisioning."""

from __future__ import annotations

import base64
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

from .config import COHORT_FILE, issued_cohort, round_context


PROOF_DIR = "/var/lib/opentsdb-release"
HELPER = "/usr/local/libexec/opentsdb-release"
PLACEMENT_STATE = f"{PROOF_DIR}/current"
PLACEMENT_PENDING = f"{PLACEMENT_STATE}.pending"
_TARGET_RE = re.compile(r"^[0-9a-f]{24}$")


def _pack(target_id: str) -> str:
    return base64.urlsafe_b64encode(
        json.dumps({"target_id": target_id}, separators=(",", ":")).encode()
    ).decode()


def _unpack(handle: str) -> str | None:
    try:
        value = json.loads(base64.urlsafe_b64decode(handle.encode()))
        target_id = value.get("target_id") if isinstance(value, dict) else None
        if isinstance(target_id, str) and _TARGET_RE.fullmatch(target_id):
            return target_id
    except Exception:
        pass
    return None


class OpenTSDBExecuteFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "opentsdb-metrics-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    def provision_principals(
        self,
        target: VulboxTarget,
        seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        assignments: dict[str, BaselinePrincipal] = {}
        accounts: list[tuple[str, str]] = []
        for attacker, seed in sorted(seeds.items()):
            principal = f"player-{seed[:12]}"
            token = seed[12:60]
            assignments[attacker] = BaselinePrincipal(
                principal_id=principal,
                credentials={"token": token},
            )
            accounts.append((principal, token))

        if len({principal for principal, _ in accounts}) != len(accounts):
            raise RuntimeError("OpenTSDB principal identity collision")
        if len({token for _, token in accounts}) != len(accounts):
            raise RuntimeError("OpenTSDB bearer credential collision")
        config_lines = sorted(
            f"{principal}={hashlib.sha256(token.encode()).hexdigest()}"
            for principal, token in accounts
        )

        encoded = base64.b64encode(("\n".join(config_lines) + "\n").encode()).decode()
        command = (
            f"printf %s {shlex.quote(encoded)} | base64 -d "
            "> /etc/opentsdb/principals.conf.new "
            "&& chown root:opentsdb /etc/opentsdb/principals.conf.new "
            "&& chmod 640 /etc/opentsdb/principals.conf.new "
            "&& mv -f /etc/opentsdb/principals.conf.new "
            "/etc/opentsdb/principals.conf "
            "&& /arena/start-opentsdb.sh"
        )
        exec_in = target.meta["exec_in_container"]
        rc, _ = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError("OpenTSDB principal configuration failed")
        self._seal_cohort(target, accounts)
        return assignments

    @staticmethod
    def _seal_cohort(target: VulboxTarget, accounts: list[tuple[str, str]]) -> None:
        """Record the issued cohort under the facility seal health verifies.

        `principals.conf` keeps only `sha256(token)`, so the raw bearer never
        otherwise reaches the box; the seal carries it because health has to
        present it to authenticate as every issued principal.
        """
        sealed = base64.b64encode(
            issued_cohort([list(account) for account in accounts]).encode()
        ).decode()
        staged = f"{COHORT_FILE}.new"
        command = (
            f"rm -f {staged} "
            f"&& printf %s {shlex.quote(sealed)} | base64 -d > {staged} "
            f"&& chown root:root {staged} "
            f"&& chmod 0400 {staged} "
            f"&& mv -f {staged} {COHORT_FILE}"
        )
        rc, _ = target.meta["exec_in_container"](target.host, command)
        if rc != 0:
            raise RuntimeError("OpenTSDB issued cohort seal failed")

    def plant(self, target: VulboxTarget, flags: Mapping[str, Flag]) -> Mapping[str, str]:
        if set(flags) != {"command"}:
            raise ValueError(f"expected command store, got {sorted(flags)}")
        return {"command": self._plant_one(target, flags["command"].value)}

    def _plant_one(self, target: VulboxTarget, value: str) -> str:
        key, expected_target = round_context(target.meta.get("round_context_seed"))
        current, pending = self._placement_states(target)
        for state in (current, pending):
            if state is None:
                continue
            state_key, state_target, _ = state
            if hmac.compare_digest(state_key, key) != hmac.compare_digest(
                state_target, expected_target
            ):
                raise RuntimeError("OpenTSDB placement state is irreconstructible")
        if current and current[0] == key:
            target_id, predecessor_id = current[1:]
        elif pending and pending[0] == key:
            target_id, predecessor_id = pending[1:]
        else:
            target_id = expected_target
            predecessor_id = current[1] if current else None
        token_path = f"{PROOF_DIR}/{target_id}.token"
        encoded_value = base64.b64encode(value.encode()).decode()
        encoded_state = base64.b64encode(
            f"{key}\n{target_id}\n{predecessor_id or '-'}\n".encode()
        ).decode()
        retained_predecessor = (
            f"! -name '{predecessor_id}.token' " if predecessor_id else ""
        )
        command = (
            f"test -x {HELPER} "
            f"&& test -d {PROOF_DIR} "
            f"&& rm -f {PROOF_DIR}/.token.new {PLACEMENT_PENDING}.new "
            f"{PLACEMENT_STATE}.new "
            f"&& printf %s {shlex.quote(encoded_state)} | base64 -d "
            f"> {PLACEMENT_PENDING}.new "
            f"&& chown root:root {PLACEMENT_PENDING}.new "
            f"&& chmod 0600 {PLACEMENT_PENDING}.new "
            f"&& mv -f {PLACEMENT_PENDING}.new {PLACEMENT_PENDING} "
            f"&& printf %s {shlex.quote(encoded_value)} | base64 -d "
            f"> {PROOF_DIR}/.token.new "
            f"&& chown root:root {PROOF_DIR}/.token.new "
            f"&& chmod 0400 {PROOF_DIR}/.token.new "
            f"&& mv -f {PROOF_DIR}/.token.new {shlex.quote(token_path)} "
            f"&& printf %s {shlex.quote(encoded_state)} | base64 -d "
            f"> {PLACEMENT_STATE}.new "
            f"&& chown root:root {PLACEMENT_STATE}.new "
            f"&& chmod 0600 {PLACEMENT_STATE}.new "
            f"&& mv -f {PLACEMENT_STATE}.new {PLACEMENT_STATE} "
            f"&& rm -f {PLACEMENT_PENDING} "
            f"&& find {PROOF_DIR} -maxdepth 1 -type f -name '*.token' "
            f"! -name '{target_id}.token' {retained_predecessor}-delete"
        )
        exec_in = target.meta["exec_in_container"]
        rc, _ = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError("OpenTSDB execution-release rotation failed")
        return _pack(target_id)

    @staticmethod
    def _placement_states(
        target: VulboxTarget,
    ) -> tuple[
        tuple[str, str, str | None] | None,
        tuple[str, str, str | None] | None,
    ]:
        command = (
            f"test -d {PROOF_DIR} && test ! -L {PROOF_DIR} || exit 45; "
            "seen=0; "
            f"if [ -e {PLACEMENT_STATE} ] || [ -L {PLACEMENT_STATE} ]; then "
            f"test -f {PLACEMENT_STATE} && test ! -L {PLACEMENT_STATE} "
            f"&& test -s {PLACEMENT_STATE} || exit 45; "
            f"printf 'current\\n'; cat {PLACEMENT_STATE}; seen=1; fi; "
            f"if [ -e {PLACEMENT_PENDING} ] || [ -L {PLACEMENT_PENDING} ]; then "
            f"test -f {PLACEMENT_PENDING} && test ! -L {PLACEMENT_PENDING} "
            f"&& test -s {PLACEMENT_PENDING} || exit 45; "
            f"printf 'pending\\n'; cat {PLACEMENT_PENDING}; seen=1; fi; "
            "if [ \"$seen\" -eq 0 ]; then "
            f"orphan=$(find {PROOF_DIR} -mindepth 1 -maxdepth 1 "
            f"-name '*.token' -print -quit) || exit 45; "
            "[ -z \"$orphan\" ] || exit 45; "
            "exit 44; fi"
        )
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, command)
        if rc == 44:
            return None, None
        if rc != 0:
            raise RuntimeError("OpenTSDB placement-state integrity failure")
        lines = (output or "").splitlines()
        states: dict[str, tuple[str, str, str | None]] = {}
        while lines:
            if len(lines) < 4 or lines[0] not in {"current", "pending"}:
                raise RuntimeError("OpenTSDB placement state is irreconstructible")
            name, key, target_id, predecessor_id = lines[:4]
            if (
                name in states
                or not re.fullmatch(r"[0-9a-f]{64}", key)
                or not _TARGET_RE.fullmatch(target_id)
                or (
                    predecessor_id != "-"
                    and not _TARGET_RE.fullmatch(predecessor_id)
                )
                or predecessor_id == target_id
            ):
                raise RuntimeError("OpenTSDB placement state is irreconstructible")
            states[name] = (
                key,
                target_id,
                None if predecessor_id == "-" else predecessor_id,
            )
            lines = lines[4:]
        if not states:
            raise RuntimeError("OpenTSDB placement state is irreconstructible")
        return states.get("current"), states.get("pending")

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        target_id = _unpack(handle)
        if target_id is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        return exec_read_observe(
            target,
            f"runuser -u opentsdb -- {HELPER} --target-{target_id}",
            expected,
        )

    def flag_id(self, handle: str) -> str | None:
        target_id = _unpack(handle)
        return f"{HELPER} --target-{target_id}" if target_id is not None else None
