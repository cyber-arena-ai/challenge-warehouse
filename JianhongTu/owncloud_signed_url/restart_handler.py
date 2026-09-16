"""Validate defender edits and gracefully replace ownCloud's PHP workers."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class OwnCloudRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "owncloud-signed-url-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, out = exec_in(target.host, "/arena/restart.sh")
        restart = CheckResult(
            "reload", rc == 0, (out or f"rc={rc}")[-240:]
        )
        return CheckResult(
            name="owncloud-signed-url-restart",
            passed=restart.passed,
            children=[restart],
        )
