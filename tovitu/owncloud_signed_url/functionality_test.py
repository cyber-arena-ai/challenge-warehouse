"""Cheap ownCloud liveness checks."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class OwnCloudFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "owncloud-signed-url-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]

        rc, _ = exec_in(target.host, "pgrep -x apache2")
        process = CheckResult("process", rc == 0, f"pgrep rc={rc}")

        tcp_command = (
            "python3 -c \"import socket; s=socket.create_connection("
            f"('127.0.0.1',{target.ports['service']}),3); s.close()\""
        )
        rc, _ = exec_in(target.host, tcp_command)
        tcp = CheckResult("tcp", rc == 0, f"localhost socket rc={rc}")

        children = [process, tcp]
        return CheckResult(
            name="owncloud-signed-url",
            passed=all(child.passed for child in children),
            children=children,
        )
