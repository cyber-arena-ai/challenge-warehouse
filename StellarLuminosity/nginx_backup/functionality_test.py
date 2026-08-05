"""Liveness probe for nginx-backup: process + tcp + protocol.

PROCESS  — nginx-ui binary alive.
TCP      — port 9000 accepts a connection.
PROTOCOL — HTTP GET / through the nginx proxy returns 2xx or 3xx.

All run via exec_in_container (privileged docker exec). The CHECKER is the
framework-run `image/checker.sh` (shipped over stdin), no longer invoked here.
"""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

PROCESS_PATTERN = "nginx-ui"


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

        return CheckResult(
            name="nginx-backup",
            passed=all(c.passed for c in (process, tcp, protocol)),
            children=[process, tcp, protocol],
        )
