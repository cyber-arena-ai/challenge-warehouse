"""FunctionalityTest for faust-birthdaygram: tcp liveness only.

The deep register/login/feed/upload round-trip (the CHECKER) moved to
`checker.py`, a network probe the Health Poller runs outside prod's trust
boundary. This keeps the shallow tcp reachability leaf.
"""
from __future__ import annotations

import logging
import socket

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _net

log = logging.getLogger(__name__)

_PORT = 3000


class BirthdaygramFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-birthdaygram-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        c = _net.make_checker(target)
        try:
            s = socket.create_connection((c.ip, _PORT), timeout=8)
            s.close()
            up, tcp_detail = True, f"connect {c.ip}:{_PORT} ok"
        except Exception as e:  # noqa: BLE001
            up, tcp_detail = False, f"connect failed: {e}"
        tcp = CheckResult(name="tcp", passed=up, detail=tcp_detail)
        return CheckResult(name="faust-birthdaygram", passed=tcp.passed, children=[tcp])
