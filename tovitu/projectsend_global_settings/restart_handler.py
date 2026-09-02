"""Reload defender-edited ProjectSend source."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class ProjectSendRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "projectsend-global-settings-restart"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        deploy = CheckResult(
            name="deploy",
            passed=rc == 0,
            detail=(output.strip() or f"rc={rc}")[-400:],
        )
        if rc == 0:
            smoke_rc, smoke_output = exec_in(
                target.host,
                "curl -fsS --max-time 10 http://127.0.0.1/index.php "
                "| grep -q ProjectSend",
            )
            smoke = CheckResult(
                name="smoke",
                passed=smoke_rc == 0,
                detail=(smoke_output.strip() or f"rc={smoke_rc}")[-200:],
            )
        else:
            smoke = CheckResult(name="smoke", passed=False, detail="deploy failed")
        return CheckResult(
            name="projectsend-restart",
            passed=deploy.passed and smoke.passed,
            children=[deploy, smoke],
        )
