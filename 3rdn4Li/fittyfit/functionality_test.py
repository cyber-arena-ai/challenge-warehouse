"""FunctionalityTest for faust-fittyfit: tcp liveness only.

The deep register/login/upload/generate/read round-trip (the CHECKER) moved to
`checker.py`, a network probe the Health Poller runs outside prod's trust
boundary. This keeps the shallow tcp reachability leaf.
"""
from __future__ import annotations

import logging

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


class FittyfitFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-fittyfit-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = _net.base_url(target)
        try:
            up = _client.check_index(base)
            tcp_detail = "GET / 200" if up else "GET / non-200"
        except Exception as e:  # noqa: BLE001
            up, tcp_detail = False, f"connect failed: {e}"
        tcp = CheckResult(name="tcp", passed=up, detail=tcp_detail)
        return CheckResult(name="faust-fittyfit", passed=tcp.passed, children=[tcp])
