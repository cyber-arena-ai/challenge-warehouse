"""FunctionalityTest for rceaas: tcp liveness only.

The deep login + mkdir/dir/echo/type/copy jail-shell round-trip (the CHECKER)
moved to `checker.py`, a network probe the Health Poller runs outside prod's
trust boundary. This keeps the shallow tcp reachability leaf.

CheckResult tree: tcp.
"""
from __future__ import annotations

import logging

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


class RceaasFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "rceaas-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        conn = _client.connect(_net.resolve(target))
        tcp = CheckResult(name="tcp", passed=conn is not None,
                          detail="connected" if conn else "connect failed")
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass
        return CheckResult(name="rceaas", passed=tcp.passed, children=[tcp])
