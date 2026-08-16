"""Shallow public liveness for Gogs; gameplay checks live in checker.py."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from .checker import resolve_host


class GogsFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "gogs-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        port = target.ports["service"]
        host = resolve_host(target)
        try:
            if host is None:
                raise OSError("public service unreachable")
            socket.create_connection((host, port), timeout=4).close()
            tcp = CheckResult("tcp", True, "public port reachable")
        except OSError as error:
            tcp = CheckResult("tcp", False, type(error).__name__)

        try:
            with urllib.request.urlopen(
                f"http://{host}:{port}/healthcheck", timeout=8
            ) as response:
                http = CheckResult("http", response.status == 200, f"HTTP {response.status}")
        except (OSError, urllib.error.URLError) as error:
            http = CheckResult("http", False, type(error).__name__)

        return CheckResult("gogs", tcp.passed and http.passed, children=[tcp, http])
