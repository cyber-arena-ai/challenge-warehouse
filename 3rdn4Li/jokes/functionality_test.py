"""FunctionalityTest for faust-jokes.

Inlines the upstream `check_service`: (1) admin account can't be re-registered
(409), (2) register+login a fresh user works, (3) a logged-in user can submit a
joke and see it in /review. Reuses the vendored `_checker/utils.py` +
`_checker/service/categories.py` unmodified.
"""
from __future__ import annotations

import html
import logging
import random
import secrets
import uuid

import requests

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _net
from ._checker import utils
from ._checker.service import categories

log = logging.getLogger(__name__)

_TIMEOUT = 10


class JokesFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-jokes-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = _net.base_url(target)
        try:
            up = requests.get(base, timeout=_TIMEOUT).status_code in (200, 302, 404)
            tcp_detail = "reachable"
        except Exception as e:  # noqa: BLE001
            up, tcp_detail = False, f"connect failed: {e}"
        tcp = CheckResult(name="tcp", passed=up, detail=tcp_detail)
        if not up:
            return CheckResult(name="faust-jokes", passed=False, children=[tcp])

        ok, detail = self._check(base)
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(name="faust-jokes",
                           passed=tcp.passed and checker.passed, children=[tcp, checker])

    def _check(self, base: str) -> tuple[bool, str]:
        # (1) admin must not be re-registerable
        try:
            r = requests.post(base + "/register",
                              data={"name": "admin", "password": "admin"}, timeout=_TIMEOUT)
        except Exception as e:  # noqa: BLE001
            return False, f"admin register: {e}"
        if r.status_code != 409:
            return False, f"admin re-register returned {r.status_code} (want 409)"

        # (2) register + login a fresh user
        creds = {"name": secrets.token_hex(16), "password": secrets.token_hex(16)}
        try:
            r = requests.post(base + "/register", data=creds, timeout=_TIMEOUT)
            if r.status_code != 200:
                return False, f"register: {r.status_code}"
            r = requests.post(base + "/login", data=creds, timeout=_TIMEOUT)
            if r.status_code != 200:
                return False, f"login: {r.status_code}"
        except Exception as e:  # noqa: BLE001
            return False, f"register/login: {e}"

        # (3) logged-in user submits a joke and sees it in /review
        s = requests.Session()
        creds2 = {"name": str(uuid.uuid4()), "password": secrets.token_hex(16)}
        try:
            if requests.post(base + "/register", data=creds2, timeout=_TIMEOUT).status_code != 200:
                return False, "submit-user register failed"
            if s.post(base + "/login", data=creds2, timeout=_TIMEOUT).status_code != 200:
                return False, "submit-user login failed"
            message = utils.generate_message()
            payload = {
                "category": random.choice(categories.category_list),
                "content": message,
                "privileges": "public",
                "event": "submit",
            }
            if s.post(base + "/profile", data=payload, timeout=_TIMEOUT).status_code != 200:
                return False, "submit joke failed"
            # /review renders the joke through Jinja autoescape, so a message
            # containing " > & comes back HTML-escaped — unescape before the
            # substring check (generate_message can return shell payloads).
            review_text = html.unescape(s.get(base + "/review", timeout=_TIMEOUT).text)
            if message not in review_text:
                return False, "submitted joke not shown in /review"
        except Exception as e:  # noqa: BLE001
            return False, f"submit/review: {e}"
        finally:
            s.close()
        return True, "admin/register/login/submit/review round-trip OK"
