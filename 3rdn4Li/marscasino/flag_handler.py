"""FlagHandler for faust-marscasino.

Inlines the upstream `place_flag` / `check_flag`: register+verify a fresh user,
then post the flag as the user's "item" on /home. Retrieve logs back in as that
user and reads the flag off their home page.
"""
from __future__ import annotations

import base64
import json
import logging
import random

import requests

from challenges.interface import SingleFlagHandler, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


def _pack(state: dict) -> str:
    return base64.b64encode(json.dumps(state).encode()).decode("ascii")


def _unpack(handle: str) -> dict | None:
    try:
        st = json.loads(base64.b64decode(handle))
        return st if isinstance(st, dict) and "flag" in st else None
    except Exception:
        return None


class MarscasinoFlagHandler(SingleFlagHandler):
    @property
    def name(self) -> str:
        return "faust-marscasino-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def plant_one(self, target: VulboxTarget, flag: str) -> str:
        base = _net.base_url(target)
        reg = _client.full_register(base)
        if reg is None:
            raise RuntimeError(f"{self.name}: register failed")
        username, password = reg
        s = requests.Session()
        resp = _client.login(s, base, username, password)
        if resp.status_code != 200 or "Wrong" in resp.text:
            raise RuntimeError(f"{self.name}: login failed")
        resp = _client.home(s, base, item=flag, item_cost=random.randint(4000, 8000))
        if resp.status_code != 200:
            raise RuntimeError(f"{self.name}: home(item) failed {resp.status_code}")
        return _pack({"flagid": username, "username": username,
                      "password": password, "flag": flag})

    def retrieve(self, target: VulboxTarget, handle: str) -> str | None:
        st = _unpack(handle)
        if st is None:
            return None
        base = _net.base_url(target)
        s = requests.Session()
        resp = _client.login(s, base, st.get("username"), st.get("password"))
        if resp.status_code != 200 or "Wrong" in resp.text:
            return None
        resp = _client.home(s, base)
        if resp.status_code != 200:
            return None
        return st["flag"] if st["flag"] in resp.text else None
