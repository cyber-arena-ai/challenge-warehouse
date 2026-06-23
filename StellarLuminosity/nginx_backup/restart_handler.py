"""Reload the nginx proxy after a defense edit.

/arena/restart.sh runs `nginx -t` (validates the defender's proxy.conf
syntax) then `nginx -s reload`. The validate step means a syntax error
surfaces in the `reload` leaf's detail rather than silently crashing nginx.

Two leaves:
  reload — exit code of restart.sh (includes nginx -t output in detail)
  smoke  — HTTP GET / through the proxy after reload; confirms the proxy
           is still serving after the config change.
"""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class NginxBackupRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "nginx-backup-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        port = target.ports["service"]

        rc, out = exec_in(target.host, RESTART_COMMAND)
        script_ok = rc == 0
        reload_ = CheckResult(
            name="reload",
            passed=script_ok,
            detail=(out.strip() or f"rc={rc}")[-200:],
        )

        if script_ok:
            rc, out = exec_in(
                target.host,
                f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 "
                f"http://127.0.0.1:{port}/",
            )
            code = out.strip() if out else ""
            smoke = CheckResult(
                name="smoke",
                passed=(rc == 0 and bool(code) and code[0] in ("2", "3")),
                detail=f"HTTP {code}" if code else f"rc={rc}",
            )
        else:
            smoke = CheckResult(
                name="smoke",
                passed=False,
                detail="skipped; restart.sh failed",
            )

        return CheckResult(
            name="nginx-backup-restart",
            passed=all(c.passed for c in (reload_, smoke)),
            children=[reload_, smoke],
        )
