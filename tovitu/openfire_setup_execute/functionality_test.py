"""Cheap internal liveness checks for Openfire's two public listeners."""

from __future__ import annotations

import shlex

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._health_identity import checker_admin_credentials


FACILITY_CLIENT = "/arena/facility_client.py"


def _ensure_checker_admin(target: VulboxTarget) -> CheckResult:
    try:
        username, password = checker_admin_credentials(target)
        command = " ".join(
            shlex.quote(part)
            for part in (FACILITY_CLIENT, "ensure-checker-admin", username, password)
        )
        rc, output = target.meta["exec_in_container"](target.host, command)
        if rc != 0:
            return CheckResult(
                name="checker-principal",
                passed=False,
                detail=f"supported admin setup failed: {(output or f'rc={rc}')[-160:]}",
            )
        return CheckResult(
            name="checker-principal",
            passed=True,
            detail="facility-derived administrator provisioned through Openfire",
        )
    except Exception as error:
        return CheckResult(
            name="checker-principal",
            passed=False,
            detail=f"setup failed: {type(error).__name__}",
        )


class OpenfireFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "openfire-setup-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("admin", "xmpp")

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        checker_principal = _ensure_checker_admin(target)
        process_rc, _ = exec_in(
            target.host,
            "test -s /run/openfire-arena.pid && kill -0 $(cat /run/openfire-arena.pid)",
        )
        process = CheckResult(
            name="process", passed=process_rc == 0, detail=f"JVM pid rc={process_rc}"
        )
        admin_rc, _ = exec_in(
            target.host,
            "curl -fsS --max-time 5 http://127.0.0.1:9090/login.jsp "
            "| grep -q 'Openfire Admin Console'",
        )
        admin = CheckResult(
            name="admin", passed=admin_rc == 0, detail=f"login page rc={admin_rc}"
        )
        xmpp_rc, _ = exec_in(
            target.host,
            "bash -c 'exec 3<>/dev/tcp/127.0.0.1/5222; exec 3>&-'",
        )
        xmpp = CheckResult(
            name="xmpp", passed=xmpp_rc == 0, detail=f"connect rc={xmpp_rc}"
        )
        children = [checker_principal, process, admin, xmpp]
        return CheckResult(
            name="openfire-setup-execute",
            passed=all(child.passed for child in children),
            children=children,
        )
