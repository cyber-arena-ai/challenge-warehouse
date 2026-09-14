"""Shallow local lifecycle checks; checker.py owns gameplay correctness."""

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
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("jenkins", False, "no exec bridge")
        port = target.ports["web"]
        try:
            controller_rc, _ = exec_in(
                target.host, "pgrep -u jenkins -f 'jenkins.war' >/dev/null"
            )
            agent_rc, _ = exec_in(
                target.host, "pgrep -u jenkins_worker -f 'agent.jar' >/dev/null"
            )
            tcp_rc, _ = exec_in(
                target.host,
                f"timeout 5 bash -c '</dev/tcp/127.0.0.1/{port}'",
            )
            http_rc, _ = exec_in(
                target.host,
                "curl -fsS --max-time 5 http://127.0.0.1:8080/login >/dev/null",
            )
        except Exception as error:  # noqa: BLE001
            return CheckResult("jenkins", False, type(error).__name__)
        children = [
            CheckResult(
                "process",
                controller_rc == 0 and agent_rc == 0,
                f"controller={controller_rc},agent={agent_rc}",
            ),
            CheckResult("tcp", tcp_rc == 0, f"rc={tcp_rc}"),
            CheckResult("http", http_rc == 0, f"rc={http_rc}"),
        ]
        return CheckResult(
            "jenkins", all(child.passed for child in children), children=children
        )
