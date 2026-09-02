"""Offline source rebuild and serving-process replacement."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class OpenTSDBRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "opentsdb-graph-command-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        compile_result = CheckResult(
            name="compile",
            passed=rc == 0,
            detail=(output or f"rc={rc}")[-200:],
        )
        if rc == 0:
            port = target.ports.get("service", 4242)
            probe = (
                "test \"$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "
                f"http://127.0.0.1:{port}/api/version)\" = 401"
            )
            smoke_rc, smoke_output = exec_in(target.host, probe)
            smoke = CheckResult(
                name="smoke",
                passed=smoke_rc == 0,
                detail="live service rejected anonymous version request"
                if smoke_rc == 0
                else (smoke_output or f"rc={smoke_rc}")[-200:],
            )
        else:
            smoke = CheckResult(name="smoke", passed=False, detail="build failed")
        return CheckResult(
            name="opentsdb-graph-command-restart",
            passed=compile_result.passed and smoke.passed,
            children=[compile_result, smoke],
        )
