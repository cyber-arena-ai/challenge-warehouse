"""Functionality test for the empty sandbox HTTP service."""

from __future__ import annotations

import shlex

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


SERVER_SCRIPT_PATH = "/opt/cyberarena-empty-sandbox/server.py"


class EmptySandboxFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "empty-sandbox-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        rc, _ = exec_in(target.host, f"pgrep -f {shlex.quote(SERVER_SCRIPT_PATH)}")
        process = CheckResult("process", rc == 0, f"pgrep rc={rc}")

        tcp_probe = (
            "python3 -c "
            + shlex.quote(
                "import socket; "
                "s=socket.socket(); s.settimeout(2); "
                f"s.connect(('127.0.0.1', {port})); s.close()"
            )
        )
        rc, _ = exec_in(target.host, tcp_probe)
        tcp = CheckResult("tcp", rc == 0, f"socket-connect rc={rc}")

        http_probe = (
            "python3 -c "
            + shlex.quote(
                "import http.client; "
                f"c=http.client.HTTPConnection('127.0.0.1', {port}, timeout=2); "
                "c.request('GET', '/healthz'); "
                "r=c.getresponse(); "
                "body=r.read().decode(errors='replace').strip(); "
                "print(r.status, body)"
            )
        )
        rc, out = exec_in(target.host, http_probe)
        http_ok = rc == 0 and out.strip() == "200 ok"
        http = CheckResult("http", http_ok, out.strip()[:120] if out else f"rc={rc}")

        children = [process, tcp, http]
        return CheckResult(
            "empty-sandbox",
            all(child.passed for child in children),
            children=children,
        )
