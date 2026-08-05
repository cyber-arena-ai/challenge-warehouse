"""CHECKER for faust-marscasino — the deep gameplay round-trip, run in the
Health Poller over the network (never execs into prod).

Register a fresh user, then run the voucher round-trip: log in, post an item,
play game2 to get a voucher, activate it, and confirm "You won". This
supersedes the old (weaker, index-page-only) image/checker.sh.
"""
from __future__ import annotations

import logging
import random
import re

import requests

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


class MarscasinoChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-marscasino-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = _net.base_url(target)
        try:
            up = requests.get(base, timeout=10).status_code in (200, 302, 404)
        except Exception as e:  # noqa: BLE001
            return CheckResult(name="checker", passed=False,
                               detail=f"connect failed: {e}"[-200:])
        if not up:
            return CheckResult(name="checker", passed=False, detail="index unreachable")

        ok, detail = self._check_voucher(base)
        return CheckResult(name="checker", passed=ok, detail=detail[-200:])

    def _check_voucher(self, base: str) -> tuple[bool, str]:
        reg = _client.full_register(base)
        if reg is None:
            return False, "register failed"
        username, password = reg
        s = requests.Session()
        resp = _client.login(s, base, username, password)
        if resp.status_code != 200 or "Wrong" in resp.text:
            return False, "login failed"
        resp = _client.home(s, base, item=_client.random_string(4),
                            item_cost=random.randint(1, 10))
        if resp.status_code != 200:
            return False, "home(item) failed"
        resp = _client.get_voucher(s, base, 3)
        if resp.status_code != 200:
            return False, "game2 (get voucher) failed"
        code = re.findall(r"Voucher: <b>(.*?)<", resp.text)
        if not code:
            return False, "could not parse voucher"
        resp = _client.activate_voucher(s, base, code[0])
        if resp.status_code != 200 or "You won" not in resp.text:
            return False, "activate voucher failed"
        return True, "register/login/voucher round-trip OK"
