"""Shallow Nginx UI process, TCP, and public-HTTP liveness."""

from __future__ import annotations

import http.client
import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class NginxUiFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nginx-ui-liveness"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            process = CheckResult("process", False, "no process observer")
        else:
            rc, _ = exec_in(target.host, "pgrep -x nginx-ui")
            process = CheckResult("process", rc == 0, f"pgrep rc={rc}")

        port = target.ports["service"]
        try:
            with socket.create_connection((target.host, port), timeout=3):
                pass
            tcp = CheckResult("tcp", True)
        except OSError as error:
            tcp = CheckResult("tcp", False, type(error).__name__)

        try:
            connection = http.client.HTTPConnection(target.host, port, timeout=5)
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                response.read()
                status = response.status
            finally:
                connection.close()
            protocol = CheckResult("protocol", 200 <= status < 400, f"HTTP {status}")
        except OSError as error:
            protocol = CheckResult("protocol", False, type(error).__name__)

        children = [process, tcp, protocol]
        return CheckResult(
            "nginx-ui", all(child.passed for child in children), children=children
        )
