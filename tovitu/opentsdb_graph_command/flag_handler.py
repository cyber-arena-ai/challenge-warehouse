"""Rotating execution-release objective and native principal provisioning."""

from __future__ import annotations

import base64
import hashlib
import json
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

from .config import checker_identity


PROOF_DIR = "/var/lib/opentsdb-release"
HELPER_DIR = "/usr/local/libexec"


def _pack(helper: str) -> str:
    return base64.urlsafe_b64encode(
        json.dumps({"helper": helper}, separators=(",", ":")).encode()
    ).decode()


def _unpack(handle: str) -> str | None:
    try:
        value = json.loads(base64.urlsafe_b64decode(handle.encode()))
        helper = value.get("helper") if isinstance(value, dict) else None
        if isinstance(helper, str) and helper.startswith(f"{HELPER_DIR}/opentsdb-release-"):
            return helper
    except Exception:
        pass
    return None


class OpenTSDBExecuteFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "opentsdb-graph-command-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ()

    def provision_principals(
        self,
        target: VulboxTarget,
        seeds: Mapping[str, str],
    ) -> Mapping[str, BaselinePrincipal]:
        assignments: dict[str, BaselinePrincipal] = {}
        checker_principal, checker_token = checker_identity(
            str(target.meta.get("team_id", ""))
        )
        config_lines = [f"{checker_principal}={checker_token}"]
        for attacker, seed in sorted(seeds.items()):
            principal = f"player-{seed[:12]}"
            token = f"arena-{seed[12:60]}"
            assignments[attacker] = BaselinePrincipal(
                principal_id=principal,
                credentials={"token": token},
            )
            config_lines.append(f"{principal}={token}")

        encoded = base64.b64encode(("\n".join(config_lines) + "\n").encode()).decode()
        command = (
            f"printf %s {shlex.quote(encoded)} | base64 -d > /etc/opentsdb/principals.conf "
            "&& chown root:opentsdb /etc/opentsdb/principals.conf "
            "&& chmod 640 /etc/opentsdb/principals.conf "
            "&& /arena/start-opentsdb.sh"
        )
        exec_in = target.meta["exec_in_container"]
        rc, _ = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError("OpenTSDB principal configuration failed")
        return assignments

    def plant(self, target: VulboxTarget, flags: Mapping[str, Flag]) -> Mapping[str, str]:
        if set(flags) != {"command"}:
            raise ValueError(f"expected command store, got {sorted(flags)}")
        return {"command": self._plant_one(target, flags["command"].value)}

    def _plant_one(self, target: VulboxTarget, value: str) -> str:
        target_id = hashlib.sha256(
            ("opentsdb-execute:" + value).encode()
        ).hexdigest()[:24]
        helper = f"{HELPER_DIR}/opentsdb-release-{target_id}"
        token_path = f"{PROOF_DIR}/{target_id}.token"
        encoded_value = base64.b64encode(value.encode()).decode()
        command = (
            f"mkdir -p {PROOF_DIR} {HELPER_DIR} "
            f"&& rm -f {PROOF_DIR}/*.token {HELPER_DIR}/opentsdb-release-* "
            f"&& printf %s {shlex.quote(encoded_value)} | base64 -d > {shlex.quote(token_path)} "
            f"&& cp /opt/opentsdb-plugin/opentsdb-proof {shlex.quote(helper)} "
            f"&& chown root:root {shlex.quote(token_path)} "
            f"&& chown root:opentsdb {shlex.quote(helper)} "
            f"&& chmod 0400 {shlex.quote(token_path)} "
            f"&& chmod 4750 {shlex.quote(helper)}"
        )
        exec_in = target.meta["exec_in_container"]
        rc, _ = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError("OpenTSDB execution-release rotation failed")
        return _pack(helper)

    def retrieve(
        self,
        target: VulboxTarget,
        handle: str,
        expected: str | None = None,
    ) -> FlagObservation:
        helper = _unpack(handle)
        if helper is None:
            return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
        return exec_read_observe(
            target,
            f"runuser -u opentsdb -- {shlex.quote(helper)}",
            expected,
        )

    def flag_id(self, handle: str) -> str | None:
        return _unpack(handle)
