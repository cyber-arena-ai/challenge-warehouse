"""Shallow liveness probe; the semantic workflow lives in checker.py."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class DolibarrFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "dolibarr-website-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]
        try:
            rc, output = exec_in(
                target.host,
                "curl -fsS --max-time 8 "
                f"http://127.0.0.1:{port}/index.php",
            )
            passed = rc == 0 and "Dolibarr" in output and "login" in output
            detail = f"curl rc={rc}; login page={passed}"
        except Exception as exc:  # infrastructure failures become a red leaf
            passed = False
            detail = f"probe failed: {type(exc).__name__}"
        return CheckResult(name="http", passed=passed, detail=detail)
