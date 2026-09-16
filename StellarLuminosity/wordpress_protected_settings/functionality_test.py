"""Shallow WordPress liveness."""

from __future__ import annotations

import json
import socket
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class WordPressFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "wordpress-site-management-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        children = [self._process(target), self._tcp(target), self._http(target)]
        return CheckResult(
            "wordpress-site-management",
            all(child.passed for child in children),
            children=children,
        )

    @staticmethod
    def _process(target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("process", False, "no exec bridge")
        apache_rc, _ = exec_in(target.host, "pgrep -x apache2")
        database_rc, _ = exec_in(target.host, "pgrep -x mariadbd")
        return CheckResult(
            "process",
            apache_rc == 0 and database_rc == 0,
            f"apache rc={apache_rc}; mariadb rc={database_rc}",
        )

    @staticmethod
    def _tcp(target: VulboxTarget) -> CheckResult:
        try:
            socket.create_connection(
                (target.host, target.ports["service"]), timeout=4
            ).close()
            return CheckResult("tcp", True, "public HTTP port reachable")
        except OSError as error:
            return CheckResult("tcp", False, str(error))

    @staticmethod
    def _http(target: VulboxTarget) -> CheckResult:
        url = (
            f"http://{target.host}:{target.ports['service']}"
            "/?rest_route=/wp/v2/posts&_fields=id&per_page=1"
        )
        try:
            with urllib.request.urlopen(url, timeout=8) as response:
                value = json.loads(response.read())
            ok = response.status == 200 and isinstance(value, list)
            return CheckResult("http", ok, f"public REST HTTP {response.status}")
        except Exception as error:  # noqa: BLE001 — liveness failures are data
            return CheckResult("http", False, type(error).__name__)
