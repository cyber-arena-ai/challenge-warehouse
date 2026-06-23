"""Respawn faust-marscasino via /arena/restart.sh (generated scaffold)."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class MarscasinoRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "faust-marscasino-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]
        rc, out = exec_in(target.host, RESTART_COMMAND)
        ok = (rc == 0)
        compile_ = CheckResult(name="compile", passed=ok,
                               detail=(out.strip() or f"rc={rc}")[-200:])
        spawn = CheckResult(name="spawn", passed=ok,
                            detail="ok" if ok else "see compile detail")
        if ok:
            probe = (f"python3 -c \"import socket; s=socket.socket(); s.settimeout(2); "
                     f"s.connect(('127.0.0.1', {port})); s.close()\"")
            srv_rc, _ = exec_in(target.host, probe)
            smoke = CheckResult(name="smoke", passed=(srv_rc == 0),
                                detail=f"socket-connect rc={srv_rc}")
        else:
            smoke = CheckResult(name="smoke", passed=False, detail="skipped; restart.sh failed")
        return CheckResult(name="faust-marscasino-restart",
                           passed=all(x.passed for x in (compile_, spawn, smoke)),
                           children=[compile_, spawn, smoke])
