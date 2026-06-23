"""Respawn btx via /arena/restart.sh.

The service is interpreted Python, so "rebuild" is a `py_compile` syntax gate
(a broken edit fails the restart, SOP §7) plus a kill/relaunch of the inetd
wrapper. The smoke leaf TCP-connects and reads the login screen (which draws
the ASCII text "Participant").
"""
from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class BtxRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "btx-restart-handler"

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
            probe = (
                "python3 - <<'PY'\n"
                "import socket,sys\n"
                f"s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1',{port}))\n"
                "data=b''\n"
                "while b'Participant' not in data and len(data) < 65536:\n"
                "    chunk=s.recv(4096)\n"
                "    if not chunk: break\n"
                "    data+=chunk\n"
                "s.close(); sys.exit(0 if b'Participant' in data else 1)\n"
                "PY"
            )
            srv_rc, _ = exec_in(target.host, probe)
            smoke = CheckResult(name="smoke", passed=(srv_rc == 0),
                                detail=f"login-page-probe rc={srv_rc}")
        else:
            smoke = CheckResult(name="smoke", passed=False,
                                detail="skipped; restart.sh failed")
        return CheckResult(name="btx-restart",
                           passed=all(x.passed for x in (compile_, spawn, smoke)),
                           children=[compile_, spawn, smoke])
