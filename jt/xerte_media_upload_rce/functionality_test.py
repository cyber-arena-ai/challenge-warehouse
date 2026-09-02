"""Shallow TCP and HTTP liveness for the Xerte deployment."""

from __future__ import annotations

import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import LOGIN_FORM_MARKER, public_get, resolve_host


class XerteFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "xerte-media-upload-rce-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = resolve_host(target.host)
        port = target.ports["service"]
        children = [self._tcp(host, port), self._http(host, port)]
        return CheckResult(name="xerte-media-upload-rce",
                           passed=all(child.passed for child in children),
                           children=children)

    @staticmethod
    def _tcp(host: str, port: int) -> CheckResult:
        try:
            with socket.create_connection((host, port), timeout=5):
                return CheckResult(name="tcp", passed=True,
                                   detail=f"{host}:{port} accepts")
        except OSError as error:
            return CheckResult(name="tcp", passed=False, detail=str(error))

    @staticmethod
    def _http(host: str, port: int) -> CheckResult:
        status, body = public_get(f"http://{host}:{port}", "index.php")
        passed = status == 200 and LOGIN_FORM_MARKER in body
        return CheckResult(name="http", passed=passed,
                           detail=f"index.php -> {status}, {len(body)} bytes")
