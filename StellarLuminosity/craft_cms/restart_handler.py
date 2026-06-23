"""Restart handler for craft-cms.

Runs /arena/restart.sh, which lints the defender's edited front controller
(`/srv/challenge/craft_cms/index.php`), copies it into the live webroot,
clears Craft's compiled caches, and gracefully reloads Apache. PHP is
interpreted, so "compile" here is `php -l` on the edited file — a syntax
error makes restart.sh fail and surfaces in the `lint` leaf.

Smoke runs the real checker (genuine Craft HTML), not just a port probe,
so a defense edit that bootstraps Apache but breaks Craft still fails.
"""

from __future__ import annotations

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"
CHECKER_COMMAND = "/arena/checker.sh"


class CraftCmsRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "craft-cms-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]

        rc, out = exec_in(target.host, RESTART_COMMAND)
        script_ok = (rc == 0)
        # restart.sh uses `set -e`; a failing `php -l` or apache reload
        # aborts it, so lint + deploy share the script's exit code.
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
            srv_rc, srv_out = exec_in(target.host, CHECKER_COMMAND)
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
            name="craft-cms-restart",
            passed=all(c.passed for c in (lint, deploy, smoke)),
            children=[lint, deploy, smoke],
        )
