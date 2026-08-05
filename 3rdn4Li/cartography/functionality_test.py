"""FunctionalityTest for faust-cartography: tcp liveness only.

The deep create/fill/read/save/load round-trip (the CHECKER) moved to
`checker.py`, a network probe the Health Poller runs outside prod's trust
boundary. This keeps the shallow tcp reachability leaf.
"""
from __future__ import annotations

import logging

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


class CartographyFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-cartography-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        conn = _client.connect(_net.resolve(target))
        tcp = CheckResult(name="tcp", passed=conn is not None,
                          detail="connected" if conn else "connect failed")
        if conn is not None:
            conn.close()
        return CheckResult(name="faust-cartography", passed=tcp.passed, children=[tcp])
