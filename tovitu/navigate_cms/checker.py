"""Deep, public-network Navigate CMS workflow checker."""

from __future__ import annotations

import json
import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _http


class NavigateChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "navigate-cms-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            exec_in = target.meta["exec_in_container"]
            rc, raw = exec_in(target.host, "cat /run/navigate/checker.json")
            if rc != 0:
                raise RuntimeError("checker principal unavailable")
            credentials = json.loads(raw)
            base = f"http://{target.host}:{target.ports['service']}/navigate"
            _, session_id = _http.login(
                base, credentials["username"], credentials["password"]
            )
            marker = secrets.token_bytes(20)
            filename = f"check-{secrets.token_hex(10)}.txt"
            _http.ordinary_upload(base, session_id, filename, marker)
            return CheckResult("checker", True, "User login/dashboard/media upload passed")
        except Exception as exc:
            return CheckResult("checker", False, f"workflow failed: {type(exc).__name__}")
