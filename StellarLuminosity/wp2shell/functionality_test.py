"""Shallow reachability probe for wp2shell (PROCESS + DATABASE + TCP).

The deep gameplay-correctness probe (normal REST behavior, batch endpoint
alive) lives in `checker.py` — a network probe the framework's HealthChecker
runs OUTSIDE prod's trust boundary, independently of this module, and merges
in as extra leaves (see `health/checker.py`). This module does NOT invoke it.
"""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class Wp2ShellFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "wp2shell-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        rc, _ = exec_in(target.host, "pgrep -x apache2")
        process = CheckResult(name="process", passed=(rc == 0), detail=f"pgrep apache2 rc={rc}")

        rc, _ = exec_in(target.host, "pgrep -x mariadbd")
        database = CheckResult(name="database", passed=(rc == 0), detail=f"pgrep mariadbd rc={rc}")

        tcp_probe = (
            f"python3 -c \"import socket; s=socket.socket(); s.settimeout(3); "
            f"s.connect(('127.0.0.1', {port})); s.close()\""
        )
        rc, _ = exec_in(target.host, tcp_probe)
        tcp = CheckResult(name="tcp", passed=(rc == 0), detail=f"socket-connect rc={rc}")

        return CheckResult(
            name="wp2shell",
            passed=all(c.passed for c in (process, database, tcp)),
            children=[process, database, tcp],
        )
