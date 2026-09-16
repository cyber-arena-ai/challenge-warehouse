"""Offline source rebuild and Jenkins controller restart."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget


class JenkinsRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "jenkins-controller-write-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("restart", False, "no exec bridge")
        try:
            rc, output = exec_in(target.host, "/arena/restart.sh")
        except Exception as error:  # noqa: BLE001
            return CheckResult("restart", False, type(error).__name__)
        text = (output or f"rc={rc}").strip()
        if rc != 0:
            errors = [line for line in text.splitlines() if "[ERROR]" in line]
            detail = "\n".join(errors[-8:])[-1200:] if errors else text[-1200:]
        else:
            detail = text[-300:]
        return CheckResult("restart", rc == 0, detail)
