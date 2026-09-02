"""External Joomla workflow checker."""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _http
from .checker_identity import checker_identities


class JoomlaChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "joomla-config-api-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            registered, administrator = checker_identities(
                str(target.meta["team_id"])
            )
            base = f"http://{target.host}:{target.ports['service']}"
            status, homepage, _ = _http.request(base + "/")
            if status != 200 or b"Cyber Arena Joomla" not in homepage:
                raise RuntimeError("Joomla homepage failed")
            _http.frontend_login(base, *registered)
            token = _http.admin_token(base, *administrator)
            marker = "Arena checker " + secrets.token_hex(12)
            patch_status, _ = _http.api_request(
                base, token, method="PATCH", payload={"fromname": marker}
            )
            read_status, config = _http.api_request(base, token)
            if (
                patch_status != 200
                or read_status != 200
                or _http.config_values(config).get("fromname") != marker
            ):
                raise RuntimeError("guarded Joomla configuration workflow failed")
            return CheckResult(
                "checker", True, "homepage/login/configuration PATCH+GET passed"
            )
        except Exception as exc:
            return CheckResult(
                "checker", False, f"workflow failed: {type(exc).__name__}"
            )
