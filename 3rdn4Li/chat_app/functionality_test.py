"""FunctionalityTest for faust-chat-app: tcp liveness only.

The deep register → create-chat → post → read-back round-trip (the CHECKER)
moved to `checker.py`, a network probe the Health Poller runs outside prod's
trust boundary. This keeps the shallow tcp reachability leaf.
"""
from __future__ import annotations

import logging

import requests

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _net

log = logging.getLogger(__name__)


class ChatAppFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-chat-app-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = _net.base_url(target)
        try:
            up = requests.get(base, timeout=8).status_code == 200
            tcp_detail = "GET / 200" if up else "GET / non-200"
        except Exception as e:  # noqa: BLE001
            up, tcp_detail = False, f"connect failed: {e}"
        tcp = CheckResult(name="tcp", passed=up, detail=tcp_detail)
        return CheckResult(name="faust-chat-app", passed=tcp.passed, children=[tcp])
