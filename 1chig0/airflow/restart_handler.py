"""Rebuild + restart Airflow via /arena/restart.sh.

Airflow is Python, so "rebuild" is a syntax gate (`compileall`) rather than a
compile. The hard part is teardown: `airflow` runs a multi-process tree and a
naive kill leaves the old api-server serving old code, so restart.sh launches the
service under `setsid` and tears down the whole process GROUP, verifying :8080 is
down before respawning. See image/restart.sh.
"""
from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class AirflowRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "airflow-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]
        rc, out = exec_in(target.host, RESTART_COMMAND)
        ok = (rc == 0)
        rebuild = CheckResult(name="rebuild", passed=ok,
                              detail=(str(out).strip() or f"rc={rc}")[-300:])
        spawn = CheckResult(name="spawn", passed=ok,
                            detail="ok" if ok else "see rebuild detail")
        if ok:
            probe = (
                "python3 - <<'PY'\n"
                "import sys,urllib.request\n"
                f"try:\n"
                f"    r=urllib.request.urlopen('http://127.0.0.1:{port}/api/v2/version',timeout=5)\n"
                "    sys.exit(0 if r.status==200 else 1)\n"
                "except Exception:\n"
                "    sys.exit(1)\n"
                "PY"
            )
            srv_rc, _ = exec_in(target.host, probe)
            smoke = CheckResult(name="smoke", passed=(srv_rc == 0),
                                detail=f"/api/v2/version rc={srv_rc}")
        else:
            smoke = CheckResult(name="smoke", passed=False, detail="skipped; rebuild failed")
        return CheckResult(name="airflow-restart",
                           passed=all(x.passed for x in (rebuild, spawn, smoke)),
                           children=[rebuild, spawn, smoke])
