"""Lightweight liveness checks for MLflow."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class MlflowFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "mlflow-tracking-liveness"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        port = target.ports["service"]
        exec_in = target.meta["exec_in_container"]
        try:
            rc, _ = exec_in(target.host, "pgrep -f '[m]lflow server'")
            process = CheckResult("process", rc == 0, f"pgrep rc={rc}")
        except Exception as error:  # noqa: BLE001 - failures are probe data
            process = CheckResult("process", False, type(error).__name__)
        try:
            with socket.create_connection((target.host, port), timeout=3):
                tcp = CheckResult("tcp", True, "connected")
        except OSError as error:
            tcp = CheckResult("tcp", False, type(error).__name__)
        try:
            with urllib.request.urlopen(
                f"http://{target.host}:{port}/health", timeout=5
            ) as response:
                status = response.status
            http = CheckResult("http", status == 200, f"HTTP {status}")
        except (OSError, urllib.error.URLError) as error:
            http = CheckResult("http", False, type(error).__name__)
        children = [process, tcp, http]
        return CheckResult(
            "mlflow-tracking-service",
            all(child.passed for child in children),
            children=children,
        )
