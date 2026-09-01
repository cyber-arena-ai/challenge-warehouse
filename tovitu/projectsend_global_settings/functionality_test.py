"""Shallow ProjectSend liveness probe."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class ProjectSendFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "projectsend-global-settings-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        try:
            rc, output = exec_in(
                target.host,
                "curl -fsS --max-time 8 http://127.0.0.1/index.php",
            )
            passed = rc == 0 and "ProjectSend" in output and "login_form" in output
            detail = f"curl rc={rc}; login page={passed}"
        except Exception as exc:
            passed = False
            detail = f"probe failed: {type(exc).__name__}"
        return CheckResult(name="http", passed=passed, detail=detail)
