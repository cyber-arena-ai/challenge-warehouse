"""Health probe for nautilus-ico: process + tcp liveness.

ico has no general protocol adapter (no LIST/PUT/GET); the real
gameplay-correctness probe is the framework-run `image/checker.sh` (shipped over
stdin into prod as the CHECKER level), no longer invoked here. Since PROTOCOL
only ever aliased that checker, it is dropped too — the CHECKER leaf now comes
from the framework.
"""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

PROCESS_PATTERN = "/srv/challenge/ico/ico"


class IcoFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nautilus-ico-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        rc, _ = exec_in(target.host, f"pgrep -f {PROCESS_PATTERN!r}")
        process = CheckResult(name="process", passed=(rc == 0), detail=f"pgrep rc={rc}")

        tcp_probe = (
            f"python3 -c \"import socket; s=socket.socket(); s.settimeout(2); "
            f"s.connect(('127.0.0.1', {port})); s.close()\""
        )
        rc, _ = exec_in(target.host, tcp_probe)
        tcp = CheckResult(name="tcp", passed=(rc == 0), detail=f"socket-connect rc={rc}")

        return CheckResult(
            name="nautilus-ico",
            passed=all(c.passed for c in (process, tcp)),
            children=[process, tcp],
        )
