"""FunctionalityTest for btx: tcp liveness only.

The deep register/login/blog round-trip (the CHECKER) moved to `checker.py`, a
network probe the Health Poller runs outside prod's trust boundary. This keeps
the shallow tcp reachability leaf.
"""
from __future__ import annotations

import logging

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


class BtxFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "btx-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        conn = _client.connect(ip)
        tcp = CheckResult(name="tcp", passed=conn is not None,
                          detail="connected" if conn else "connect failed")
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass
        return CheckResult(name="btx", passed=tcp.passed, children=[tcp])
