"""Shallow external liveness checks for Listmonk."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class ListmonkFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "listmonk-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        process_ok = False
        if exec_in is not None:
            try:
                rc, _ = exec_in(target.host, "pgrep -f '[l]istmonk/bin/listmonk'")
                process_ok = rc == 0
            except Exception:  # noqa: BLE001 — liveness failures are observations
                pass
        process = CheckResult("process", process_ok, "backend process probe")

        port = target.ports["service"]
        tcp_ok = False
        try:
            socket.create_connection((target.host, port), timeout=3).close()
            tcp_ok = True
        except OSError:
            pass
        tcp = CheckResult("tcp", tcp_ok, "public port probe")

        http_ok = False
        detail = "health request skipped"
        if tcp_ok:
            try:
                with urllib.request.urlopen(
                    f"http://{target.host}:{port}/health", timeout=8
                ) as response:
                    http_ok = response.status == 200
                    detail = f"GET /health HTTP {response.status}"
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                detail = f"GET /health failed: {type(error).__name__}"
        http = CheckResult("http", http_ok, detail)
        children = [process, tcp, http]
        return CheckResult(
            "listmonk", all(child.passed for child in children), children=children
        )
