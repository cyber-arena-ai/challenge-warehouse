"""Restart handler for pyload-rce — respawn via /arena/restart.sh."""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class PyloadRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "pyload-rce-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["web"]

        rc, out = exec_in(target.host, RESTART_COMMAND)
        ok = (rc == 0)
        compile_ = CheckResult(name="compile", passed=ok, detail=(out.strip() or f"rc={rc}")[-200:])
        spawn = CheckResult(name="spawn", passed=ok, detail="ok" if ok else "see compile detail")

        if ok:
            probe = (
                "python3 -c \"import urllib.request,sys; "
                f"r=urllib.request.urlopen('http://127.0.0.1:{port}/', timeout=4); "
                "sys.exit(0 if r.status<400 else 1)\""
            )
            srv_rc, _ = exec_in(target.host, probe)
            smoke = CheckResult(name="smoke", passed=(srv_rc == 0), detail=f"GET / rc={srv_rc}")
        else:
            smoke = CheckResult(name="smoke", passed=False, detail="skipped; restart.sh failed")

        return CheckResult(
            name="pyload-rce-restart",
            passed=all(c.passed for c in (compile_, spawn, smoke)),
            children=[compile_, spawn, smoke],
        )
