"""Rebuild and replace Nginx UI from defender-edited source."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class NginxUiRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "nginx-ui-restart"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("restart", False, "no restart executor")
        rc, output = exec_in(target.host, "/arena/restart.sh")
        rebuild = CheckResult("rebuild", rc == 0, (output or f"rc={rc}")[-300:])
        serving = False
        detail = "skipped"
        if rebuild.passed:
            smoke_rc, smoke_output = exec_in(
                target.host,
                "curl -fsS --max-time 10 http://127.0.0.1:9000/ >/dev/null",
            )
            serving = smoke_rc == 0
            detail = (smoke_output or f"rc={smoke_rc}")[-300:]
        smoke = CheckResult("serving", serving, detail)
        return CheckResult(
            "restart", rebuild.passed and smoke.passed, children=[rebuild, smoke]
        )
