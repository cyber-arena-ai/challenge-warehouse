"""Shallow in-container Grafana liveness checks."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class GrafanaFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "grafana-protected-contact-point-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        port = target.ports["service"]
        children: list[CheckResult] = []
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            children.append(CheckResult("process", False, "no exec bridge"))
        else:
            command = (
                "pid=$(cat /run/grafana/grafana.pid 2>/dev/null) && "
                "test -n \"$pid\" && kill -0 \"$pid\" && "
                "test \"$(awk '/^Uid:/{print $2}' /proc/$pid/status)\" = 472"
            )
            try:
                rc, _ = exec_in(target.host, command)
            except Exception:  # noqa: BLE001
                rc = 1
            children.append(CheckResult("process", rc == 0, f"rc={rc}"))
        if exec_in is None:
            tcp_rc = http_rc = 1
        else:
            tcp_command = (
                "python3 -c \"import socket; s=socket.create_connection("
                f"('127.0.0.1',{port}),3); s.close()\""
            )
            tcp_rc, _ = exec_in(target.host, tcp_command)
            http_rc, _ = exec_in(
                target.host,
                "curl -fsS --max-time 8 "
                f"http://127.0.0.1:{port}/api/health >/dev/null",
            )
        children.append(CheckResult("tcp", tcp_rc == 0, f"rc={tcp_rc}"))
        children.append(CheckResult("http", http_rc == 0, f"rc={http_rc}"))
        return CheckResult(
            "grafana", all(child.passed for child in children), children=children,
        )
