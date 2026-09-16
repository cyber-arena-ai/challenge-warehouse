"""Offline rebuild and restart handler for Listmonk."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class ListmonkRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "listmonk-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, out = exec_in(target.host, "/arena/restart.sh")
        out = out or ""
        tail = (out.strip() or f"rc={rc}")[-400:]
        children = [
            CheckResult("compile", "listmonk-restart: compile ok" in out, tail),
            CheckResult(
                "spawn",
                "listmonk: process started pid=" in out,
                "new backend launched" if "listmonk: process started pid=" in out else tail,
            ),
            CheckResult(
                "readiness",
                rc == 0 and "listmonk: service ready on :9000" in out,
                "GET /health ready" if rc == 0 else tail,
            ),
        ]
        return CheckResult(
            "listmonk-restart",
            all(child.passed for child in children),
            children=children,
        )
