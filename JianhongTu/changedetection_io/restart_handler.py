"""Validate editable source and restart changedetection.io."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class ChangedetectionIoRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "changedetection-io-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        detail = ((output or "").strip() or f"rc={rc}")[-600:]
        return CheckResult("changedetection-io-restart", rc == 0, detail)
