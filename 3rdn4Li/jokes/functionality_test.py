"""FunctionalityTest for faust-jokes: tcp liveness only.

The deep admin/register/login/submit/review round-trip (the CHECKER) moved to
`checker.py`, a network probe the Health Poller runs outside prod's trust
boundary. This keeps the shallow tcp reachability leaf.
"""
from __future__ import annotations

import logging

import requests

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _net

log = logging.getLogger(__name__)

_TIMEOUT = 10


class JokesFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-jokes-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = _net.base_url(target)
        try:
            up = requests.get(base, timeout=_TIMEOUT).status_code in (200, 302, 404)
            tcp_detail = "reachable"
        except Exception as e:  # noqa: BLE001
            up, tcp_detail = False, f"connect failed: {e}"
        tcp = CheckResult(name="tcp", passed=up, detail=tcp_detail)
        return CheckResult(name="faust-jokes", passed=tcp.passed, children=[tcp])
