"""FlagHandler for faust-chat-app.

Plants the flag as a private chat message between two freshly registered users,
and retrieves it by logging back in as the victim and reading the chat. The
per-plant state (usernames, password, chat id) is packed into the opaque handle
returned by `plant`. Uses the HTTP client in `_checker/helpers.py`.
"""
from __future__ import annotations

import base64
import json
import logging
import secrets

from challenges.interface import SingleFlagHandler, VulboxTarget

from . import _net
from ._checker import helpers

log = logging.getLogger(__name__)


def _pack(state: dict) -> str:
    return base64.b64encode(json.dumps(state).encode()).decode("ascii")


def _unpack(handle: str) -> dict | None:
    try:
        st = json.loads(base64.b64decode(handle))
        return st if isinstance(st, dict) and "flag" in st else None
    except Exception:
        return None


class ChatAppFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "faust-chat-app-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        """Plant the flag as a private chat message between two fresh users.

        Mirrors the upstream `place_flag`; the flag-id is the victim
        username (returned to attackers in the live game).
        """
        base = _net.base_url(target)
        username = helpers.randomUser()
        guest = helpers.randomUser()
        password = secrets.token_hex()

        ok, data = helpers.register(base, guest, password)
        if not ok:
            raise RuntimeError(f"{self.name}: register guest failed: {data}")
        ok, token = helpers.register(base, username, password)
        if not ok:
            raise RuntimeError(f"{self.name}: register user failed: {token}")
        ok, chat_id = helpers.create_chat(base, token, guest)
        if not ok:
            raise RuntimeError(f"{self.name}: create_chat failed: {chat_id}")
        ok, data = helpers.post_message(base, token, chat_id, f"Hey {guest}!")
        if not ok:
            raise RuntimeError(f"{self.name}: post_message failed: {data}")
        ok, data = helpers.post_message(
            base, token, chat_id, f"here is the secret: {flag}")
        if not ok:
            raise RuntimeError(f"{self.name}: post flag failed: {data}")

        # flag-id (= username) + per-tick state -> handle (was store_state)
        return _pack({
            "flag_id": username,
            "username": username,
            "password": password,
            "chat_id": chat_id,
            "flag": flag,
        })

    def retrieve(self, target: VulboxTarget, handle: str) -> str | None:
        """Read the flag back via the victim's own login. None on miss."""
        st = _unpack(handle)
        if st is None:
            return None
        base = _net.base_url(target)
        username, password = st.get("username"), st.get("password")
        chat_id, flag = st.get("chat_id"), st["flag"]
        if not username or not password:
            return None

        ok, token = helpers.login(base, username, password)
        if not ok:
            return None
        ok, messages = helpers.get_messages(base, token, chat_id)
        if not ok:
            return None
        for message in messages:
            if message.get("content") == f"here is the secret: {flag}":
                return flag
        return None

    def flag_id(self, handle: str) -> str | None:
        """Attack-info hook: the PUBLIC identifier the attacker targets — the
        victim username whose private chatroom holds this round's flag message
        (already computed in plant). None for an unparseable handle; never the
        flag value."""
        st = _unpack(handle)
        return st.get("flag_id") if st else None
