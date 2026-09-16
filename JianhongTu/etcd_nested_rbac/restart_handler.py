"""Rebuild defender-edited etcd source and replace the serving process."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class EtcdRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "etcd-configuration-store-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        output = output or ""
        detail = (output.strip() or f"rc={rc}")[-500:]
        children = [
            CheckResult("compile", "etcd-restart: compile ok" in output, detail),
            CheckResult("spawn", "etcd-restart: process started" in output, detail),
            CheckResult(
                "readiness",
                rc == 0 and "etcd-restart: service ready" in output,
                detail,
            ),
        ]
        return CheckResult(
            "etcd-configuration-store-restart",
            all(child.passed for child in children),
            children=children,
        )
