"""Layered Jenkins health and legitimate archive workflow checks."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class JenkinsFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "jenkins-controller-write-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["web"]

        rc_controller, _ = exec_in(
            target.host, "pgrep -u jenkins -f 'jenkins.war' >/dev/null"
        )
        rc_agent, _ = exec_in(
            target.host, "pgrep -u jenkins_worker -f 'agent.jar' >/dev/null"
        )
        process = CheckResult(
            name="process",
            passed=(rc_controller == 0 and rc_agent == 0),
            detail=f"controller rc={rc_controller}, agent rc={rc_agent}",
        )

        tcp_command = (
            "python3 -c \"import socket; s=socket.socket(); s.settimeout(3); "
            f"s.connect(('127.0.0.1',{port})); s.close()\""
        )
        rc, _ = exec_in(target.host, tcp_command)
        tcp = CheckResult(name="tcp", passed=(rc == 0), detail=f":{port} rc={rc}")

        http_command = (
            "python3 -c \"import base64,urllib.request; "
            "r=urllib.request.Request('http://127.0.0.1:8080/api/json',"
            "headers={'Authorization':'Basic '+base64.b64encode("
            "b'player:arena-player-password').decode()}); "
            "x=urllib.request.urlopen(r,timeout=5); "
            "assert x.status==200 and x.headers['X-Jenkins'] in ('2.554','2.555')\""
        )
        rc, _ = exec_in(target.host, http_command)
        http = CheckResult(
            name="http", passed=(rc == 0), detail=f"authenticated API rc={rc}"
        )

        rc, output = exec_in(target.host, "/arena/sshd_check.sh")
        sshd = CheckResult(
            name="sshd",
            passed=(rc == 0),
            detail=(output.strip() or f"rc={rc}")[-300:],
        )

        rc, output = exec_in(target.host, "/arena/checker.sh")
        checker = CheckResult(
            name="checker",
            passed=(rc == 0),
            detail=(output.strip() or f"rc={rc}")[-300:],
        )

        children = [process, tcp, http, sshd, checker]
        return CheckResult(
            name="jenkins-controller-write",
            passed=all(child.passed for child in children),
            children=children,
        )
