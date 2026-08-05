"""Liveness probe for craft-cms: process + tcp.

Craft has no separable line protocol; PROTOCOL only ever aliased the CHECKER,
so it is dropped too. The CHECKER is the framework-run `image/checker.sh`
(shipped over stdin), no longer invoked here.
"""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class CraftCmsFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "craft-cms-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        rc, _ = exec_in(target.host, "pgrep -x apache2")
        process = CheckResult(name="process", passed=(rc == 0), detail=f"pgrep rc={rc}")

        tcp_probe = (
            f"python3 -c \"import socket; s=socket.socket(); s.settimeout(3); "
            f"s.connect(('127.0.0.1', {port})); s.close()\""
        )
        rc, _ = exec_in(target.host, tcp_probe)
        tcp = CheckResult(name="tcp", passed=(rc == 0), detail=f"socket-connect rc={rc}")

        return CheckResult(
            name="craft-cms",
            passed=all(c.passed for c in (process, tcp)),
            children=[process, tcp],
        )
