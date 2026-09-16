"""Shallow public Gogs liveness; checker.py owns the workflow SLA."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class GogsFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "gogs-code-collaboration-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = target.host
        port = target.ports["service"]
        try:
            socket.create_connection((host, port), timeout=4).close()
            tcp = CheckResult("tcp", True, "public port reachable")
        except OSError as error:
            tcp = CheckResult("tcp", False, type(error).__name__)
        try:
            with urllib.request.urlopen(
                f"http://{host}:{port}/healthcheck", timeout=8
            ) as response:
                http = CheckResult(
                    "http", response.status == 200, f"HTTP {response.status}"
                )
        except (OSError, urllib.error.URLError) as error:
            http = CheckResult("http", False, type(error).__name__)
        return CheckResult(
            "gogs-code-collaboration",
            tcp.passed and http.passed,
            children=[tcp, http],
        )
