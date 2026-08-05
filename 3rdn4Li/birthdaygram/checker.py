"""CHECKER for faust-birthdaygram — the deep gameplay round-trip, run in the
Health Poller over the network (never execs into prod).

Register + login, read the feed, upload a private image and confirm it shows up
in the user's own view, then log out. Reuses the vendored `_checker/utils.py`
UNMODIFIED. This supersedes the old (weaker, index-page-only) image/checker.sh.
"""
from __future__ import annotations

import logging
import socket

import requests  # noqa: F401  (utils uses it; kept explicit for clarity)

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _net
from ._checker import utils

log = logging.getLogger(__name__)

_PORT = 3000


class BirthdaygramChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-birthdaygram-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        c = _net.make_checker(target)
        try:
            s = socket.create_connection((c.ip, _PORT), timeout=8)
            s.close()
        except Exception as e:  # noqa: BLE001
            return CheckResult(name="checker", passed=False,
                               detail=f"connect failed: {e}"[-200:])
        ok, detail = self._check(c)
        return CheckResult(name="checker", passed=ok, detail=detail[-200:])

    def _check(self, c) -> tuple[bool, str]:
        session = __import__("requests").session()
        username = utils.generate_name()
        password = utils.generate_password()
        try:
            utils.check_register(c, session, username, password)
        except Exception as e:  # noqa: BLE001
            return False, f"register: {e}"
        try:
            utils.check_login(c, session, username, password)
        except Exception as e:  # noqa: BLE001
            return False, f"login: {e}"
        try:
            utils.get_feed_pic_nums(c)
        except Exception as e:  # noqa: BLE001
            return False, f"feed: {e}"

        # upload a private image and confirm it appears in the user's own view
        try:
            priv_bytes = utils.fromPILImageToBytes(utils.create_rand_png_no_save())
            utils.upload_private_image(c, session, priv_bytes)
            view = utils.get_view(c, session, username)
            if view.find(utils.imageToStr(priv_bytes)) == -1:
                return False, "uploaded private image not found in own view"
        except Exception as e:  # noqa: BLE001
            return False, f"private image round-trip: {e}"

        try:
            utils.logout(c)
        except Exception:  # noqa: BLE001
            pass
        return True, "register/login/feed/upload-private/view round-trip OK"
