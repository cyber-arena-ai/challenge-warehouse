"""Restart handler for wp2shell.

Runs /arena/restart.sh, which lints the defender's edited copies of the two
vulnerable core files (`class-wp-query.php`, `class-wp-rest-server.php`)
under `/srv/challenge/wp2shell/`, deploys whichever were touched into the
real WordPress core tree, and gracefully reloads Apache. PHP is interpreted,
so "compile" here is `php -l` on each edited file — a syntax error in either
aborts the script and surfaces in the `lint` leaf.

Smoke re-checks the live HTTP port (and that WordPress still answers), not
just that Apache is up, so a defense edit that reloads cleanly but breaks the
site still fails restart.
"""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"


class Wp2ShellRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "wp2shell-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]

        rc, out = exec_in(target.host, RESTART_COMMAND)
        script_ok = (rc == 0)
        # restart.sh uses `set -e`; a failing `php -l` or apache reload aborts
        # it, so lint + deploy share the script's exit code.
        lint = CheckResult(
            name="lint",
            passed=script_ok,
            detail=(out.strip() or f"rc={rc}")[-300:],
        )
        deploy = CheckResult(
            name="deploy",
            passed=script_ok,
            detail="ok" if script_ok else "see lint detail",
        )

        if script_ok:
            smoke_probe = (
                "python3 -c \"import urllib.request; "
                "urllib.request.urlopen('http://127.0.0.1/', timeout=8).read()\""
            )
            srv_rc, srv_out = exec_in(target.host, smoke_probe)
            smoke = CheckResult(
                name="smoke",
                passed=(srv_rc == 0),
                detail=(srv_out.strip() or f"rc={srv_rc}")[-200:],
            )
        else:
            smoke = CheckResult(
                name="smoke",
                passed=False,
                detail="skipped; restart.sh failed",
            )

        return CheckResult(
            name="wp2shell-restart",
            passed=all(c.passed for c in (lint, deploy, smoke)),
            children=[lint, deploy, smoke],
        )
