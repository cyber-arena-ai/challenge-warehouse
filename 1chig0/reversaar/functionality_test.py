"""FunctionalityTest for reversaar: http reachability only.

Keeps the shallow reachability leaf: GET the web root and expect HTTP 200. The
deep login + array reverse round-trip (the CHECKER) moved to `checker.py`, a
network probe the Health Poller runs outside prod's trust boundary.

CheckResult tree: http.
"""
from __future__ import annotations

import logging

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


class ReversaarFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "reversaar-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        up = _client.ping(ip)
        http = CheckResult(name="http", passed=up,
                           detail="GET / -> 200" if up else "web root unreachable")
        return CheckResult(name="reversaar", passed=http.passed, children=[http])
