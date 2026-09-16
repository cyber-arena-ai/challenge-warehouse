"""Deploy defender-edited WordPress source and restart Apache."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class WordPressRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "wordpress-site-management-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        output = output or ""
        detail = (output.strip() or f"rc={rc}")[-500:]
        children = [
            CheckResult("lint", "wordpress-restart: lint ok" in output, detail),
            CheckResult("deploy", "wordpress-restart: deploy ok" in output, detail),
            CheckResult(
                "readiness",
                rc == 0 and "wordpress-restart: service ready" in output,
                detail,
            ),
        ]
        return CheckResult(
            "wordpress-site-management-restart",
            all(child.passed for child in children),
            children=children,
        )
