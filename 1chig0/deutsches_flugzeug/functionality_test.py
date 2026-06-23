"""FunctionalityTest for deutsches-flugzeug.

Exercises the core gameplay the way the upstream saarCTF `check_integrity`
does, condensed to what proves the service works end to end:
signup -> login -> profile -> create flight -> book flight -> find it in the
public listing. None of this forges a ticket, so the legitimate flow must keep
working after the defender patches the JWT library.

CheckResult tree: http + checker.
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


class DeutschesFlugzeugFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "deutsches-flugzeug-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        port = target.ports["service"]

        try:
            r = httpx.get(_client.base_url(ip, port) + "/auth/login",
                          timeout=8.0, follow_redirects=True)
            reachable = r.status_code == 200
            http_detail = f"GET /auth/login -> {r.status_code}"
        except httpx.HTTPError as e:
            reachable = False
            http_detail = f"connect failed: {type(e).__name__}: {e}"

        http = CheckResult(name="http", passed=reachable, detail=http_detail)
        if not reachable:
            return CheckResult(name="deutsches-flugzeug", passed=False,
                               children=[http])

        ok, detail = self._check(ip, port)
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(name="deutsches-flugzeug",
                           passed=http.passed and checker.passed,
                           children=[http, checker])

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
