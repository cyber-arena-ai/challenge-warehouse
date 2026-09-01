"""Shallow authenticated reachability probe for OpenTSDB."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from .client import OpenTSDBClient
from .config import SERVICE_PORT


class OpenTSDBFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "opentsdb-graph-command-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        port = target.ports.get("service", SERVICE_PORT)
        try:
            status, _ = OpenTSDBClient(target.host, port).request("/api/version")
            passed = status == 401
            detail = f"anonymous version request status={status}"
        except (OSError, ValueError) as error:
            passed = False
            detail = f"{type(error).__name__}: {error}"
        leaf = CheckResult(name="http", passed=passed, detail=detail[-200:])
        return CheckResult(
            name="opentsdb-graph-command",
            passed=leaf.passed,
            children=[leaf],
        )
