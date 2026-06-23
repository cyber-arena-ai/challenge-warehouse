"""4-level health probe for craft-cms.

Craft has no separable line protocol, so PROTOCOL aliases to CHECKER.
The real gameplay-correctness probe is /arena/checker.sh, which GETs a
Craft control-panel page and verifies the response is genuine Craft HTML
(not a cheese stub swapped in to pass a naive port check).
"""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

CHECKER_COMMAND = "/arena/checker.sh"


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

        rc, out = exec_in(target.host, CHECKER_COMMAND)
        checker_ok = (rc == 0)
        checker = CheckResult(
            name="checker",
            passed=checker_ok,
            detail=(out.strip() or f"rc={rc}")[-200:],
        )
        protocol = CheckResult(
            name="protocol",
            passed=checker_ok,
            detail="aliased to CHECKER",
        )

        return CheckResult(
            name="craft-cms",
            passed=all(c.passed for c in (process, tcp, protocol, checker)),
            children=[process, tcp, protocol, checker],
        )
