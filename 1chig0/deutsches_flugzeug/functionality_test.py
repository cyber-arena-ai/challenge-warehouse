"""FunctionalityTest for deutsches-flugzeug: http reachability only.

Keeps the shallow reachability leaf: GET /auth/login must answer HTTP 200. The
deep signup -> login -> profile -> create -> book -> list round-trip (the
CHECKER) moved to `checker.py`, a network probe the Health Poller runs outside
prod's trust boundary.

CheckResult tree: http.
"""
from __future__ import annotations

import logging

import httpx

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


class DeutschesFlugzeugFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "deutsches-flugzeug-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        port = target.ports["service"]

        try:
            r = httpx.get(_client.base_url(ip, port) + "/auth/login",
                          timeout=8.0, follow_redirects=True)
            reachable = r.status_code == 200
            http_detail = f"GET /auth/login -> {r.status_code}"
        except httpx.HTTPError as e:
            reachable = False
            http_detail = f"connect failed: {type(e).__name__}: {e}"

        http = CheckResult(name="http", passed=reachable, detail=http_detail)
        return CheckResult(name="deutsches-flugzeug", passed=http.passed,
                           children=[http])
