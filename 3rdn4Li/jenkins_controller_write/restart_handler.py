"""Restart Jenkins with the defender-selected bundled release."""

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
        exec_in = target.meta["exec_in_container"]
        rc, output = exec_in(target.host, "/arena/restart.sh")
        restart = CheckResult(
            name="restart",
            passed=(rc == 0),
            detail=(output.strip() or f"rc={rc}")[-300:],
        )

        if rc == 0:
            probe_cmd = (
                "python3 -c \"import base64,json,urllib.request; "
                "q=urllib.request.Request('http://127.0.0.1:8080/computer/"
                "untrusted-agent/api/json',headers={'Authorization':'Basic '+"
                "base64.b64encode(b'player:arena-player-password').decode()}); "
                "d=json.load(urllib.request.urlopen(q,timeout=5)); "
                "assert d['offline'] is False\""
            )
            probe_rc, _ = exec_in(target.host, probe_cmd)
            ready = CheckResult(
                name="agent",
                passed=(probe_rc == 0),
                detail=f"online API rc={probe_rc}",
            )
        else:
            ready = CheckResult(name="agent", passed=False, detail="restart failed")

        return CheckResult(
            name="jenkins-controller-write-restart",
            passed=(restart.passed and ready.passed),
            children=[restart, ready],
        )
