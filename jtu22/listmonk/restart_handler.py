"""Rebuild and restart listmonk after a defender source edit.

``/arena/restart.sh`` rebuilds the editable Go source, atomically replaces the
binary, and waits for the new backend's local health endpoint. PostgreSQL stays
running, so application and flag state persist. The orchestration health flow
runs the authoritative external checker afterward; restart never invokes a
checker baked into production.
"""

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
        detail = (out.strip() or f"rc={rc}")[-300:]
        compile_res = CheckResult(
            "compile",
            "listmonk-restart: compile ok" in out,
            detail,
        )
        spawn_ok = "listmonk: process started pid=" in out
        spawn = CheckResult(
            "spawn",
            spawn_ok,
            "new listmonk process launched" if spawn_ok else detail,
        )
        ready_ok = rc == 0 and "listmonk: service ready on :9000" in out
        ready = CheckResult(
            "readiness",
            ready_ok,
            "GET /health ready" if ready_ok else detail,
        )

        return CheckResult(
            "listmonk-restart",
            all(c.passed for c in (compile_res, spawn, ready)),
            children=[compile_res, spawn, ready],
        )
