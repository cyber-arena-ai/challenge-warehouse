"""FunctionalityTest for faust-treasury: tcp liveness only.

The deep add/view/update round-trip (the CHECKER) moved to `checker.py`, a
network probe the Health Poller runs outside prod's trust boundary. This keeps
the shallow tcp reachability leaf (a plain socket connect on the menu port).
"""
from __future__ import annotations

import logging
import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _net

log = logging.getLogger(__name__)

_PORT = 6789


class TreasuryFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-treasury-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        try:
            s = socket.create_connection((ip, _PORT), timeout=8)
            s.close()
            up, tcp_detail = True, "connected"
        except Exception:  # noqa: BLE001
            up, tcp_detail = False, "connect failed"
        tcp = CheckResult(name="tcp", passed=up, detail=tcp_detail)
        return CheckResult(name="faust-treasury", passed=tcp.passed, children=[tcp])
