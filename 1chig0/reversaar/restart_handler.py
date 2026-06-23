"""Respawn reversaar via /arena/restart.sh.

The service is compiled C (the reversaar.cgi binary + the array.so blob baked into
.tmp.bin), so "rebuild" recompiles from /srv/challenge/reversaar/app — a broken C
edit fails the build and fails the restart (compile gate, SOP §7) — then relaunches
nginx + spawn-fcgi(fcgiwrap). The smoke leaf HTTP-probes GET / on 7331.
"""
from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class ReversaarRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "reversaar-restart-handler"

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
                "code=$(curl -s -o /dev/null -w '%{http_code}' "
                f"http://127.0.0.1:{port}/ || true); "
                "test \"$code\" = 200"
            )
            srv_rc, _ = exec_in(target.host, probe)
            smoke = CheckResult(name="smoke", passed=(srv_rc == 0),
                                detail=f"GET / probe rc={srv_rc}")
        else:
            smoke = CheckResult(name="smoke", passed=False, detail="skipped; build failed")
        return CheckResult(name="reversaar-restart",
                           passed=all(x.passed for x in (compile_, spawn, smoke)),
                           children=[compile_, spawn, smoke])
