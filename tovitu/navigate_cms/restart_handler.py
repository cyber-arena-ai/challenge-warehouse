"""Reload edited Navigate CMS PHP source."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class NavigateRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "navigate-cms-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        compile_result = CheckResult("compile", rc == 0, (output or f"rc={rc}")[-200:])
        spawn = CheckResult("spawn", rc == 0, "Apache reload" if rc == 0 else "skipped")
        smoke = CheckResult("smoke", False, "skipped")
        if rc == 0:
            port = target.ports["service"]
            smoke_rc, _ = exec_in(
                target.host,
                f"curl -fsS --max-time 5 http://127.0.0.1:{port}/navigate/login.php >/dev/null",
            )
            smoke = CheckResult("smoke", smoke_rc == 0, f"login.php rc={smoke_rc}")
        return CheckResult(
            "navigate-cms-restart",
            all(c.passed for c in (compile_result, spawn, smoke)),
            children=[compile_result, spawn, smoke],
        )
