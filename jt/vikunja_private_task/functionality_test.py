"""Shallow process, TCP, and HTTP liveness for Vikunja."""

from __future__ import annotations

import json
import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import VikunjaApi, resolve_host


class VikunjaFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "vikunja-private-task-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = resolve_host(target.host)
        port = target.ports["service"]
        children = [self._process(target), self._tcp(host, port), self._http(host, port)]
        return CheckResult(name="vikunja-private-task",
                           passed=all(child.passed for child in children),
                           children=children)

    def _process(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult(name="process", passed=False, detail="no exec bridge")
        try:
            rc, out = exec_in(target.host,
                              "pgrep -u vikunja -f '/arena/vikunja web' | head -1")
        except Exception as error:  # noqa: BLE001
            return CheckResult(name="process", passed=False, detail=f"pgrep: {error}")
        pid = (out or "").strip()
        return CheckResult(name="process", passed=(rc == 0 and bool(pid)),
                           detail=f"UID 1000 pid={pid or 'none'}")

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
        try:
            status, raw = VikunjaApi(f"http://{host}:{port}").request(
                "GET", "/api/v1/info")
            info = json.loads(raw or b"{}")
        except Exception as error:  # noqa: BLE001
            return CheckResult(name="http", passed=False, detail=str(error))
        passed = status == 200 and info.get("version") == "v2.2.0"
        return CheckResult(name="http", passed=passed,
                           detail=f"info -> {status}, version={info.get('version')!r}")
