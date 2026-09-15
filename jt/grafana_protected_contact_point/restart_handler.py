"""Rebuild and restart Grafana from defender-editable source."""

from __future__ import annotations

import secrets
import shlex
import time

from challenges.interface import CheckResult, RestartHandler, VulboxTarget

RESTART_TIMEOUT = 600
RESTART_STATE_DIR = "/run/grafana"


class GrafanaRestartHandler(RestartHandler):
    @property
    def name(self) -> str:
        return "grafana-protected-contact-point-restart"

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("restart", False, "no exec bridge")
        nonce = secrets.token_hex(8)
        status_path = f"{RESTART_STATE_DIR}/restart-{nonce}.status"
        log_path = f"{RESTART_STATE_DIR}/restart-{nonce}.log"
        worker = (
            "rc=0; /arena/restart.sh || rc=$?; "
            f"printf '%s\\n' \"$rc\" > {status_path}.new; "
            f"mv -f {status_path}.new {status_path}; exit \"$rc\""
        )
        launch = (
            f"rm -f {status_path} {status_path}.new {log_path}; "
            f"nohup setsid bash -c {shlex.quote(worker)} "
            f"</dev/null >{log_path} 2>&1 & echo $!"
        )
        try:
            rc, out = exec_in(target.host, launch)
        except Exception:  # noqa: BLE001
            return CheckResult("restart", False, "restart exec raised")
        pid = (out or "").strip()
        if rc != 0 or not pid.isdigit():
            return CheckResult("restart", False, "restart launch failed")

        deadline = time.monotonic() + RESTART_TIMEOUT
        result = ""
        while time.monotonic() < deadline:
            try:
                poll_rc, result = exec_in(
                    target.host,
                    f"if test -s {status_path}; then printf done:; cat {status_path}; "
                    f"elif kill -0 {pid} 2>/dev/null; then printf running; "
                    "else printf lost; fi",
                )
            except Exception:  # noqa: BLE001
                return CheckResult("restart", False, "restart poll raised")
            if poll_rc != 0:
                return CheckResult("restart", False, "restart poll failed")
            result = (result or "").strip()
            if result.startswith("done:") or result == "lost":
                break
            time.sleep(5)
        else:
            try:
                exec_in(target.host, f"kill -TERM -{pid} 2>/dev/null || true")
            except Exception:  # noqa: BLE001, S110
                pass
            return CheckResult("restart", False, "restart timed out")

        try:
            _, log = exec_in(target.host, f"tail -c 500 {log_path} 2>/dev/null || true")
        except Exception:  # noqa: BLE001
            log = ""
        detail = (log or "")[-500:]
        passed = result == "done:0"
        if result == "lost" and not detail:
            detail = "restart worker exited without status"
        return CheckResult(
            "restart", passed, detail,
            children=[CheckResult("offline_build_reload", passed, detail)],
        )
