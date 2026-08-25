"""Liveness + legitimate-workflow health check for changedetection.io.

Liveness (process/tcp/http) is a fast fail; on top of it we run the authenticated
benign-XPath watch round-trip from ``checker.py`` so that amputating the XPath
filtering feature (or disabling the operator API) fails CHECKER instead of
silently passing while the attack surface is gone.
"""

from __future__ import annotations

import socket
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from .checker import ChangedetectionIoChecker, resolve_host


class ChangedetectionIoFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "changedetection-io-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, _ = exec_in(target.host, "pgrep -f '[c]hangedetection.py'")
        process = CheckResult("process", rc == 0, f"backend pgrep rc={rc}")

        host = resolve_host(target)
        tcp_ok = host is not None
        if tcp_ok:
            try:
                socket.create_connection((host, target.ports["service"]), 3).close()
            except OSError:
                tcp_ok = False
        tcp = CheckResult("tcp", tcp_ok, "public port reachable" if tcp_ok else "unreachable")

        if not tcp_ok:
            http = CheckResult("http", False, "request skipped")
        else:
            try:
                with urllib.request.urlopen(
                    f"http://{host}:{target.ports['service']}/", timeout=8
                ) as response:
                    status = response.status
                http = CheckResult("http", status == 200, f"GET / HTTP {status}")
            except Exception as error:  # noqa: BLE001 - liveness failure is data
                http = CheckResult("http", False, f"GET / failed: {type(error).__name__}")

        children = [process, tcp, http]
        # Only exercise the (heavier, ~seconds) authenticated watch workflow once
        # the service is actually up — otherwise the liveness failure is the signal.
        if all(child.passed for child in children):
            children.append(ChangedetectionIoChecker().run(target))
        return CheckResult(
            "changedetection-io",
            all(child.passed for child in children),
            children=children,
        )
