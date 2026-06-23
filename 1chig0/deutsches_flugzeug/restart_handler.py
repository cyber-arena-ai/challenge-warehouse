"""Respawn deutsches-flugzeug via /arena/restart.sh.

The service is a Python Flask app served by gunicorn. "Rebuild" here is a
`py_compile` gate over the edited source (a broken edit fails the restart,
SOP §7) plus a kill/relaunch of the gunicorn daemon. The smoke leaf HTTP-probes
localhost:5000.
"""
from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class DeutschesFlugzeugRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "deutsches-flugzeug-restart-handler"

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
                "import sys, urllib.request\n"
                f"try:\n"
                f"    r = urllib.request.urlopen('http://127.0.0.1:{port}/auth/login', timeout=5)\n"
                "    sys.exit(0 if r.status == 200 else 1)\n"
                "except Exception:\n"
                "    sys.exit(1)\n"
                "PY"
            )
            srv_rc, _ = exec_in(target.host, probe)
            smoke = CheckResult(name="smoke", passed=(srv_rc == 0),
                                detail=f"http-probe rc={srv_rc}")
        else:
            smoke = CheckResult(name="smoke", passed=False,
                                detail="skipped; compile failed")
        return CheckResult(name="deutsches-flugzeug-restart",
                           passed=all(x.passed for x in (compile_, spawn, smoke)),
                           children=[compile_, spawn, smoke])
