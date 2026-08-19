"""Rebuild and replace the defender-edited Gogs server."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class GogsRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "gogs-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        compile_ok = "GOGS_RESTART_COMPILE_OK" in output
        spawn_ok = "GOGS_RESTART_SPAWN_OK" in output
        ready_ok = "GOGS_RESTART_READY_OK" in output and rc == 0
        children = [
            CheckResult("compile", compile_ok, "ok" if compile_ok else output[-200:]),
            CheckResult("spawn", spawn_ok, "ok" if spawn_ok else output[-200:]),
            CheckResult("readiness", ready_ok, "HTTP healthcheck" if ready_ok else output[-200:]),
        ]
        return CheckResult(
            "gogs-restart",
            all(child.passed for child in children),
            children=children,
        )
