"""Shallow liveness checks for Listmonk.

The compound subscriber query/export workflow lives in `checker.py`, which the
health poller runs outside the production container's trust boundary.
"""
from __future__ import annotations

import socket
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from .checker import resolve_host

TIMEOUT = 8


class ListmonkFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "listmonk-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "object_store")

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        rc, _ = exec_in(target.host, "pgrep -f '[l]istmonk/bin/listmonk'")
        process = CheckResult("process", rc == 0, f"backend pgrep rc={rc}")
        rc, _ = exec_in(target.host, "pgrep -x minio")
        object_process = CheckResult("object-process", rc == 0, f"minio pgrep rc={rc}")

        host = resolve_host(target)
        tcp_ok = host is not None
        if tcp_ok:
            try:
                socket.create_connection((host, port), 3).close()
            except OSError:
                tcp_ok = False
        tcp = CheckResult("tcp", tcp_ok, "public port reachable" if tcp_ok else "unreachable")

        if not tcp_ok:
            health = CheckResult("http", False, "health request skipped")
        else:
            try:
                with urllib.request.urlopen(
                    f"http://{host}:{port}/health", timeout=TIMEOUT
                ) as response:
                    ok = response.status == 200
                health = CheckResult("http", ok, f"GET /health HTTP {response.status}")
            except Exception as exc:  # noqa: BLE001 - liveness failure is data
                health = CheckResult("http", False, f"GET /health failed: {type(exc).__name__}")

        object_tcp_ok = host is not None
        if object_tcp_ok:
            try:
                socket.create_connection((host, target.ports["object_store"]), 3).close()
            except OSError:
                object_tcp_ok = False
        object_tcp = CheckResult(
            "object-tcp",
            object_tcp_ok,
            "public object-store port reachable" if object_tcp_ok else "unreachable",
        )

        children = [process, object_process, tcp, health, object_tcp]
        return CheckResult("listmonk", all(child.passed for child in children), children=children)
