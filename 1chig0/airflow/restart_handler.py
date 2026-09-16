"""Reload edited Airflow source through the image's lifecycle command."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class AirflowRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "airflow-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("airflow-restart", False, "facility exec unavailable")
        rc, output = exec_in(target.host, "/arena/restart.sh")
        lines = str(output).strip().splitlines()
        detail = lines[-1][-240:] if lines else f"rc={rc}"
        return CheckResult("airflow-restart", rc == 0, detail)
