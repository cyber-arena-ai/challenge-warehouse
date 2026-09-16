"""Rebuild and restart Grafana from defender-editable source."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class GrafanaRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "grafana-protected-contact-point-restart"

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("restart", False, "no exec bridge")
        try:
            rc, out = exec_in(target.host, "/arena/restart.sh")
        except Exception:  # noqa: BLE001
            return CheckResult("restart", False, "restart exec raised")
        detail = (out or "")[-500:]
        return CheckResult(
            "restart", rc == 0, detail,
            children=[CheckResult("offline_build_reload", rc == 0, detail)],
        )
