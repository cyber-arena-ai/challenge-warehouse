"""Restart handler for n8n-fileread.

Runs /arena/restart.sh, which restarts n8n without resetting the admin
credential, replaces the active workflow with the defender's edited
workflow.json, and reactivates it.
"""

from __future__ import annotations

import shlex

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_COMMAND = "/arena/restart.sh"
NORMAL_SUBMIT_SMOKE = (
    "marker=n8n-restart-smoke-$(date +%s%N); "
    "tmp=$(mktemp); "
    "printf '%s' \"$marker\" > \"$tmp\"; "
    "body=$(curl -sf --max-time 20 "
    "-F 'Full Name=Restart Check' "
    "-F 'Email=restart-check@arena.local' "
    "-F \"document=@${tmp};type=text/plain\" "
    "http://127.0.0.1:5678/form/document-upload); "
    "rm -f \"$tmp\"; "
    "printf '%s' \"$body\" | grep -F \"$marker\""
)


class N8nRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "n8n-fileread-restart-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta["exec_in_container"]
        rc, out = exec_in(target.host, RESTART_COMMAND)
        script_ok = (rc == 0)
        restart = CheckResult(
            name="restart",
            passed=script_ok,
            detail=(out.strip() or f"rc={rc}")[-400:],
        )

        if script_ok:
            srv_rc, srv_out = exec_in(
                target.host,
                f"sh -c {shlex.quote(NORMAL_SUBMIT_SMOKE)}",
            )
            smoke = CheckResult(
                name="smoke",
                passed=(srv_rc == 0),
                detail=(
                    "normal document submission returned uploaded bytes"
                    if srv_rc == 0
                    else (srv_out.strip() or f"rc={srv_rc}")[-300:]
                ),
            )
        else:
            smoke = CheckResult(name="smoke", passed=False, detail="skipped; restart.sh failed")

        return CheckResult(
            name="n8n-fileread-restart",
            passed=all(c.passed for c in (restart, smoke)),
            children=[restart, smoke],
        )
