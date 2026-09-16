"""Shallow Navigate CMS health leaves."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class NavigateFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "navigate-cms-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]
        rc, _ = exec_in(target.host, "pgrep -x apache2 >/dev/null && pgrep -x mariadbd >/dev/null")
        process = CheckResult("process", rc == 0, f"apache/mariadb rc={rc}")
        rc, _ = exec_in(
            target.host,
            f"python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',{port}),3);s.close()\"",
        )
        tcp = CheckResult("tcp", rc == 0, f"connect rc={rc}")
        rc, _ = exec_in(
            target.host,
            f"curl -fsS --max-time 5 http://127.0.0.1:{port}/navigate/login.php >/dev/null",
        )
        protocol = CheckResult("protocol", rc == 0, f"login.php rc={rc}")
        return CheckResult(
            "navigate-cms",
            all(child.passed for child in (process, tcp, protocol)),
            children=[process, tcp, protocol],
        )
