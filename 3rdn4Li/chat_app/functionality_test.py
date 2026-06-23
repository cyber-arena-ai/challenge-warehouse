"""FunctionalityTest for faust-chat-app.

Runs a full register → create-chat → post → login-as-guest → read-back
round-trip, asserting the guest can read the message. Returns a CheckResult
tree (`tcp` + `checker` leaves) the panel renders per leaf.
"""
from __future__ import annotations

import logging
import secrets

import requests

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _net
from ._checker import helpers

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
        if not up:
            return CheckResult(name="faust-chat-app", passed=False, children=[tcp])

        try:
            ok, detail = self._round_trip(base)
        except Exception as e:  # noqa: BLE001 — broken gameplay is a failed leaf, never a raise
            ok, detail = False, f"checker error: {type(e).__name__}: {e}"
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(
            name="faust-chat-app",
            passed=tcp.passed and checker.passed,
            children=[tcp, checker],
        )

    def _round_trip(self, base: str) -> tuple[bool, str]:
        username = helpers.randomUser()
        guest = helpers.randomUser()
        password = secrets.token_hex()
        gpassword = secrets.token_hex()
        secret = helpers.randomUser()

        ok, token = helpers.register(base, username, password)
        if not ok:
            return False, f"register: {token}"
        ok, gtoken = helpers.register(base, guest, gpassword)
        if not ok:
            return False, f"register guest: {gtoken}"
        ok, chat_id = helpers.create_chat(base, token, guest)
        if not ok:
            return False, f"create_chat: {chat_id}"
        ok, data = helpers.post_message(base, token, chat_id, secret)
        if not ok:
            return False, f"post_message: {data}"
        ok, gtoken = helpers.login(base, guest, gpassword)
        if not ok:
            return False, f"login guest: {gtoken}"
        ok, chats = helpers.get_chats(base, gtoken)
        if not ok:
            return False, f"get_chats: {chats}"
        for chat in chats:
            ok, messages = helpers.get_messages(base, gtoken, chat["id"])
            if not ok:
                return False, f"get_messages: {messages}"
            for message in messages:
                if message["content"] != secret:
                    return False, "guest saw a foreign message"
        return True, "register/chat/post/read round-trip OK"
