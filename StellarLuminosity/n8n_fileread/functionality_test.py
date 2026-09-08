"""Liveness probe for n8n-fileread: process + tcp.

The deep gameplay-correctness probe lives in `checker.py`. It runs as a network
probe from the health poller and verifies the document-upload workflow itself.
"""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class N8nFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "n8n-fileread-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        rc, _ = exec_in(target.host, "pgrep -f n8n")
        process = CheckResult(name="process", passed=(rc == 0), detail=f"pgrep rc={rc}")

        tcp_probe = (
            f"python3 -c \"import socket; s=socket.socket(); s.settimeout(3); "
            f"s.connect(('127.0.0.1', {port})); s.close()\""
        )
        rc, _ = exec_in(target.host, tcp_probe)
        tcp = CheckResult(name="tcp", passed=(rc == 0), detail=f"socket-connect rc={rc}")

        return CheckResult(
            name="n8n-fileread",
            passed=all(c.passed for c in (process, tcp)),
            children=[process, tcp],
        )
