"""Shallow SuiteCRM process, TCP, and HTTP liveness."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._api import resolve_host


class SuiteCrmFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "suitecrm-security-groups-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = resolve_host(target.host)
        port = target.ports["service"]
        children = [
            self._process(target),
            self._tcp(host, port),
            self._http(host, port),
        ]
        return CheckResult(
            "suitecrm-security-groups",
            all(child.passed for child in children),
            children=children,
        )

    @staticmethod
    def _process(target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("process", False, "no exec bridge")
        command = (
            "p=$(pgrep -u www-data -f 'php-fpm: pool www' | head -1) || exit 1; "
            "n=$(pgrep -u www-data -f 'nginx: worker process' | head -1) || exit 1; "
            "m=$(pgrep -u www-data -x mariadbd | head -1) || exit 1; "
            "for x in $p $n $m; do awk '/^Uid:/{print $2}' /proc/$x/status; done"
        )
        try:
            rc, out = exec_in(target.host, command)
        except Exception as error:  # noqa: BLE001
            return CheckResult("process", False, str(error))
        uids = (out or "").strip().split()
        passed = rc == 0 and uids == ["82", "82", "82"]
        return CheckResult(
            "process", passed,
            "PHP/nginx/MariaDB workers UID 82" if passed else f"rc={rc}",
        )

    @staticmethod
    def _tcp(host: str, port: int) -> CheckResult:
        try:
            with socket.create_connection((host, port), timeout=5):
                return CheckResult("tcp", True, f"{host}:{port} accepts")
        except OSError as error:
            return CheckResult("tcp", False, str(error))

    @staticmethod
    def _http(host: str, port: int) -> CheckResult:
        url = f"http://{host}:{port}/index.php?action=Login&module=Users"
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                status = response.status
                body = response.read(200_000)
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read(200_000)
        except OSError as error:
            return CheckResult("http", False, str(error))
        passed = status == 200 and b"SuiteCRM" in body and b"user_name" in body
        return CheckResult("http", passed, f"login page status={status}")
