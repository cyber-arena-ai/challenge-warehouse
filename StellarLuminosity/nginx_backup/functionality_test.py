"""4-level health probe for nginx-backup.

PROCESS  — nginx-ui binary alive.
TCP      — port 9000 accepts a connection.
PROTOCOL — HTTP GET / through the nginx proxy returns 2xx or 3xx.
CHECKER  — /arena/checker.sh (same HTTP check; separate leaf for the panel).

All four run via exec_in_container (privileged docker exec). The CHECKER
intentionally does not probe /api/backup so a successful defense still passes.
"""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

PROCESS_PATTERN = "nginx-ui"
CHECKER_COMMAND = "/arena/checker.sh"


class NginxBackupFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nginx-backup-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        rc, _ = exec_in(target.host, f"pgrep -f {PROCESS_PATTERN!r}")
        process = CheckResult(
            name="process",
            passed=(rc == 0),
            detail=f"pgrep rc={rc}",
        )

        tcp_probe = (
            f"python3 -c \"import socket; s=socket.socket(); s.settimeout(2); "
            f"s.connect(('127.0.0.1', {port})); s.close()\""
        )
        rc, _ = exec_in(target.host, tcp_probe)
        tcp = CheckResult(
            name="tcp",
            passed=(rc == 0),
            detail=f"socket-connect rc={rc}",
        )

        rc, out = exec_in(
            target.host,
            f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 "
            f"http://127.0.0.1:{port}/",
        )
        code = out.strip() if out else ""
        proto_ok = rc == 0 and bool(code) and code[0] in ("2", "3")
        protocol = CheckResult(
            name="protocol",
            passed=proto_ok,
            detail=f"HTTP {code}" if code else f"rc={rc}",
        )

        rc, out = exec_in(target.host, CHECKER_COMMAND)
        checker = CheckResult(
            name="checker",
            passed=(rc == 0),
            detail=(out.strip() or f"rc={rc}")[-200:],
        )

        return CheckResult(
            name="nginx-backup",
            passed=all(c.passed for c in (process, tcp, protocol, checker)),
            children=[process, tcp, protocol, checker],
        )
