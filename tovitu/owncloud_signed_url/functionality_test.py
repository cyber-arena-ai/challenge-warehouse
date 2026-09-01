"""Cheap liveness and trusted setup for the external ownCloud checker."""

from __future__ import annotations

import shlex

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._health_identity import checker_credentials


FACILITY_CLIENT = "/arena/facility_client.py"


def _ensure_checker_users(target: VulboxTarget) -> CheckResult:
    try:
        identities = checker_credentials(target)
        exec_in = target.meta["exec_in_container"]
        for username, password in identities:
            command = " ".join(
                shlex.quote(part)
                for part in (FACILITY_CLIENT, "ensure-user", username, password)
            )
            rc, output = exec_in(target.host, command)
            if rc != 0:
                return CheckResult(
                    "checker-principals",
                    False,
                    f"supported OCS setup failed: {(output or f'rc={rc}')[-120:]}",
                )
        return CheckResult(
            "checker-principals", True, "ordinary users provisioned through OCS"
        )
    except Exception as error:
        return CheckResult(
            "checker-principals", False, f"setup failed: {type(error).__name__}"
        )


class OwnCloudFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "owncloud-signed-url-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        setup = _ensure_checker_users(target)
        exec_in = target.meta["exec_in_container"]

        rc, _ = exec_in(target.host, "pgrep -x apache2")
        process = CheckResult("process", rc == 0, f"pgrep rc={rc}")

        tcp_command = (
            "python3 -c \"import socket; s=socket.create_connection("
            f"('127.0.0.1',{target.ports['service']}),3); s.close()\""
        )
        rc, _ = exec_in(target.host, tcp_command)
        tcp = CheckResult("tcp", rc == 0, f"localhost socket rc={rc}")

        children = [setup, process, tcp]
        return CheckResult(
            name="owncloud-signed-url",
            passed=all(child.passed for child in children),
            children=children,
        )
