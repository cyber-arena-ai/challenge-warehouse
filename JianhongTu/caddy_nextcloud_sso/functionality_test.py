"""Shallow process, TCP, HTTP, and pinned-identity liveness."""

from __future__ import annotations

import json
import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._api import resolve_host, unauthenticated_status


class CaddyNextcloudFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "caddy-nextcloud-sso-functionality"

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
            self._identity(target),
        ]
        return CheckResult("caddy-nextcloud-sso",
                           all(child.passed for child in children),
                           children=children)

    @staticmethod
    def _process(target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("process", False, "no exec bridge")
        command = (
            "c=$(cat /run/caddy/caddy.pid 2>/dev/null) || exit 1; "
            "cu=$(awk '/^Uid:/{print $2}' /proc/$c/status); "
            "p=$(pgrep -u service -f 'php-fpm: pool www' | head -1) || exit 1; "
            "pu=$(awk '/^Uid:/{print $2}' /proc/$p/status); "
            "printf '%s %s %s %s\\n' \"$c\" \"$cu\" \"$p\" \"$pu\""
        )
        try:
            rc, out = exec_in(target.host, command)
        except Exception as error:  # noqa: BLE001
            return CheckResult("process", False, str(error))
        fields = (out or "").strip().split()
        passed = rc == 0 and len(fields) == 4 and fields[1::2] == ["1000", "1000"]
        return CheckResult("process", passed,
                           "Caddy/PHP worker UID 1000" if passed else f"rc={rc}")

    @staticmethod
    def _tcp(host: str, port: int) -> CheckResult:
        try:
            with socket.create_connection((host, port), timeout=5):
                return CheckResult("tcp", True, f"{host}:{port} accepts")
        except OSError as error:
            return CheckResult("tcp", False, str(error))

    @staticmethod
    def _http(host: str, port: int) -> CheckResult:
        try:
            status = unauthenticated_status(f"http://{host}:{port}")
        except Exception as error:  # noqa: BLE001
            return CheckResult("http", False, str(error))
        return CheckResult("http", status == 401, f"unauthenticated -> {status}")

    @staticmethod
    def _identity(target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("identity", False, "no exec bridge")
        try:
            rc, out = exec_in(target.host, "/arena/facility.py status")
            status = json.loads((out or "").strip()) if rc == 0 else {}
        except Exception as error:  # noqa: BLE001
            return CheckResult("identity", False, str(error))
        passed = (
            status.get("caddy") == "v2.11.1"
            and status.get("nextcloud") == "32.0.13"
            and status.get("user_saml") == "8.2.1"
            and status.get("groupfolders") == "20.1.18"
        )
        return CheckResult("identity", passed,
                           "pinned stack ready" if passed else "identity mismatch")
