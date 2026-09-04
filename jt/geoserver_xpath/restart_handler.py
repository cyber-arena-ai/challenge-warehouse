"""Rebuild the edited GeoTools reactor and reload GeoServer."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class GeoServerRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "geoserver-xpath-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        rc, out = target.meta["exec_in_container"](
            target.host, "/arena/restart.sh"
        )
        detail = ((out or "").strip() or f"rc={rc}")[-800:]
        return CheckResult("geoserver-xpath-restart", rc == 0, detail)
