"""Protocol client for faust-marscasino. Pure HTTP. `baseurl` carries a
trailing slash like the original `self._baseurl`.
"""
from __future__ import annotations

import logging
import random
import re
import string

import requests

log = logging.getLogger(__name__)


def random_string(length=12):
    length = random.randint(6, 15) if length <= 0 else length
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def random_name():
    t = "".join(random.choice(string.ascii_letters) for _ in range(4))
    return t + "".join(random.choice(string.digits) for _ in range(4))


def register(baseurl, name, password, fcode=""):
    ip = ":".join("".join(random.choice(string.hexdigits) for _ in range(4)) for _ in range(8))
    return requests.post(baseurl + "register",
                         data={"username": name, "password": password, "ip": ip, "fcode": fcode})


def verify(baseurl, code):
    return requests.get(baseurl + "verify?code=%s" % code)


def full_register(baseurl, fcode="", name=True):
    """Register + verify a fresh user. Returns (username, password) or None."""
    for _ in range(3):
        if name:
            username, password = random_name(), random_string()
        else:
            username, password = random_string(0), random_string(0)
        resp = register(baseurl, username, password, fcode=fcode)
        if resp.status_code != 200:
            continue
        activate = re.findall(r".{8}-.{4}-.{4}-.{4}-.{12}", resp.text)
        if not activate:
            continue
        if verify(baseurl, activate[0]).status_code != 200:
            continue
        return username, password
    return None


def login(session, baseurl, name, password):
    return session.post(baseurl + "login", data={"username": name, "password": password})


def home(session, baseurl, item=None, item_cost=None):
    if item:
        return session.post(baseurl + "home", data={"item": item, "item_cost": item_cost})
    return session.get(baseurl + "home")


def get_voucher(session, baseurl, bet):
    return session.post(baseurl + "game2", data={"bet": bet})


def activate_voucher(session, baseurl, voucher):
    return session.post(baseurl + "voucher", data={"voucher": voucher})
