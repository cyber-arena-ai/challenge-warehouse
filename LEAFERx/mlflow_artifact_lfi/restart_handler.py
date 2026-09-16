"""Re-import edited MLflow source and restart the tracking server."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class MlflowRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "mlflow-tracking-restart"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        restart = CheckResult(
            "restart",
            rc == 0,
            (output or f"rc={rc}").strip()[-300:],
        )
        return CheckResult("mlflow-restart", restart.passed, children=[restart])
