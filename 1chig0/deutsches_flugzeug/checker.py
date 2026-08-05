"""CHECKER for deutsches-flugzeug — the deep gameplay round-trip, run in the
Health Poller over the network (never execs into prod).

Exercises the core gameplay the way the upstream saarCTF `check_integrity` does,
condensed to what proves the service works end to end: signup -> login ->
profile -> create flight -> book flight -> find it in the public listing. None of
this forges a ticket, so the legitimate flow must keep working after the defender
patches the JWT library. This supersedes the old (weaker, login-page-only)
image/checker.sh.
"""
from __future__ import annotations

import logging
import secrets
import string

import httpx

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)

_ALNUM = string.ascii_lowercase + string.digits


def _rand(n: int) -> str:
    return "".join(secrets.choice(_ALNUM) for _ in range(n))


class DeutschesFlugzeugChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "deutsches-flugzeug-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        port = target.ports["service"]
        ok, detail = self._check(ip, port)
        return CheckResult(name="checker", passed=ok, detail=detail[-200:])

    def _check(self, ip: str, port: int) -> tuple[bool, str]:
        user = "chk" + _rand(12)
        pw = _rand(20)
        marker = "chk-" + _rand(16)
        try:
            with _client.new_session(ip, port) as sess:
                if not _client.ensure_account(sess, user, pw):
                    return False, "signup/login failed"

                if user not in sess.get("/dasProfil").text:
                    return False, "profile page did not reflect the user"

                flug_id = _client.create_flight(
                    sess, pw, vip_info="nichts geheimes",
                    beschreibung=f"Checkerflug {marker}")
                if flug_id is None:
                    return False, "flight creation failed"

                _client.book_flight(sess, flug_id)

                found = _client.find_flight_by_marker(sess, marker)
                if found is None:
                    return False, "created flight not found in public listing"

                return True, ("signup/login/profile/create/book/list round-trip "
                              f"OK (flug_id={flug_id})")
        except (httpx.HTTPError, _client.ClientError) as e:
            return False, f"protocol error: {type(e).__name__}: {e}"
