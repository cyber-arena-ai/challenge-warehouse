"""FunctionalityTest for faust-marscasino.

Register a fresh buyer and run the voucher round-trip, then register a seller,
publish a low-cost marker item, buy it as the first user, and verify its content.
CheckResult tree: tcp + checker.
"""
from __future__ import annotations

import logging
import random
import re

import requests

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


class MarscasinoFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-marscasino-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = _net.base_url(target)
        try:
            up = requests.get(base, timeout=10).status_code in (200, 302, 404)
            tcp_detail = "reachable"
        except Exception as e:  # noqa: BLE001
            up, tcp_detail = False, f"connect failed: {e}"
        tcp = CheckResult(name="tcp", passed=up, detail=tcp_detail)
        if not up:
            return CheckResult(name="faust-marscasino", passed=False, children=[tcp])

        ok, detail = self._check_gameplay(base)
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(name="faust-marscasino",
                           passed=tcp.passed and checker.passed, children=[tcp, checker])

    def _check_gameplay(self, base: str) -> tuple[bool, str]:
        buyer = buyer_password = seller = seller_password = None
        buyer_session = requests.Session()
        seller_session = requests.Session()
        try:
            reg = _client.full_register(base)
            if reg is None:
                return False, "buyer register failed"
            buyer, buyer_password = reg
            resp = _client.login(buyer_session, base, buyer, buyer_password)
            if resp.status_code != 200 or "Wrong" in resp.text:
                return False, "buyer login failed"

            resp = _client.get_voucher(buyer_session, base, 3)
            if resp.status_code != 200:
                return False, "game2 (get voucher) failed"
            code = re.findall(r"Voucher: <b>(.*?)<", resp.text)
            if not code:
                return False, "could not parse voucher"
            resp = _client.activate_voucher(buyer_session, base, code[0])
            if resp.status_code != 200 or "You won" not in resp.text:
                return False, "activate voucher failed"

            seller_reg = _client.full_register(base)
            if seller_reg is None:
                return False, "seller register failed"
            seller, seller_password = seller_reg
            resp = _client.login(seller_session, base, seller, seller_password)
            if resp.status_code != 200 or "Wrong" in resp.text:
                return False, "seller login failed"
            marker = _client.random_string(20)
            # The buyer started with 10 coins and spent 3 on game2, so it always
            # retains at least 7 even when the legitimate voucher pays out zero.
            item_cost = random.randint(1, 7)
            resp = _client.home(
                seller_session, base, item=marker, item_cost=item_cost
            )
            if resp.status_code != 200:
                return False, "seller home(item) failed"

            resp = _client.buy(buyer_session, base, seller)
            if resp.status_code != 200 or marker not in resp.text:
                return False, "cross-user buy failed"
            return True, "register/login/voucher/buy round-trip OK"
        finally:
            # Checker accounts are disposable. Best-effort cleanup prevents
            # health probes from polluting the player-visible user/item lists.
            for session, username, password in (
                (seller_session, seller, seller_password),
                (buyer_session, buyer, buyer_password),
            ):
                if username is None or password is None:
                    continue
                try:
                    _client.delete_account(session, base, username, password)
                except requests.RequestException:
                    pass
