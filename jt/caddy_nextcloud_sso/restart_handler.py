"""Offline Caddy source rebuild and service replacement."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class CaddyNextcloudRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "caddy-nextcloud-sso-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        rc, out = target.meta["exec_in_container"](
            target.host, "/arena/restart.sh")
        detail = ((out or "").strip() or f"rc={rc}")[-600:]
        return CheckResult("caddy-nextcloud-sso-restart", rc == 0, detail)
