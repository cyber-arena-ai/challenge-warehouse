"""CHECKER for faust-marscasino — the deep gameplay round-trip, run in the
Health Poller over the network (never execs into prod).

Register a buyer, run the voucher round-trip (log in, play game2 to get a
voucher, activate it, confirm "You won"), recruit a seller through the buyer's
random friend code, publish a low-cost marker item, buy it cross-user, and play
one valid roulette round. This supersedes the old (weaker, index-page-only)
image/checker.sh.
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

            friend_code = _client.referral_code(buyer_session, base)
            if friend_code is None:
                return False, "could not read buyer friend code"

            seller_reg = _client.full_register(base, fcode=friend_code)
            if seller_reg is None:
                return False, "referred seller register failed"
            seller, seller_password = seller_reg
            resp = _client.login(seller_session, base, seller, seller_password)
            if resp.status_code != 200 or "Wrong" in resp.text:
                return False, "seller login failed"
            resp = _client.home(seller_session, base)
            if resp.status_code != 200 or "You have 50 coins" not in resp.text:
                return False, "referral bonus failed"
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

            resp = _client.play_roulette(buyer_session, base, 1, "0")
            result = re.search(
                r"The number was\s+(\d+)\s+and you win\s+(\d+)\s+coins",
                resp.text,
            )
            if resp.status_code != 200 or result is None:
                return False, "roulette round failed"
            number, win = (int(value) for value in result.groups())
            expected_win = 36 if number == 0 else 0
            if win != expected_win:
                return False, "roulette zero payout was inconsistent with the draw"
            return True, "register/login/voucher/referral/buy/roulette round-trip OK"
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
