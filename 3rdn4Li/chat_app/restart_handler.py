"""Respawn faust-chat-app via /arena/restart.sh.

Interpreted service: restart.sh byte-compiles the edited source then
relaunches gunicorn and self-gates on an HTTP health check. Three leaves:
compile + spawn share the script's exit code (it runs under `set -e`);
smoke is an independent TCP probe confirming the new instance bound the
port.
"""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class ChatAppRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "faust-chat-app-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        rc, out = exec_in(target.host, RESTART_COMMAND)
        script_ok = (rc == 0)
        compile_ = CheckResult(
            name="compile",
            passed=script_ok,
            detail=(out.strip() or f"rc={rc}")[-200:],
        )
        spawn = CheckResult(
            name="spawn",
            passed=script_ok,
            detail="ok" if script_ok else "see compile detail",
        )

        if script_ok:
            tcp_probe = (
                f"python3 -c \"import socket; s=socket.socket(); s.settimeout(2); "
                f"s.connect(('127.0.0.1', {port})); s.close()\""
            )
            srv_rc, _ = exec_in(target.host, tcp_probe)
            smoke = CheckResult(
                name="smoke",
                passed=(srv_rc == 0),
                detail=f"socket-connect rc={srv_rc}",
            )
        else:
            smoke = CheckResult(
                name="smoke",
                passed=False,
                detail="skipped; restart.sh failed",
            )

        return CheckResult(
            name="faust-chat-app-restart",
            passed=all(c.passed for c in (compile_, spawn, smoke)),
            children=[compile_, spawn, smoke],
        )
