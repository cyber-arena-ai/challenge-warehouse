"""FunctionalityTest for reversaar.

Mirrors the upstream checker's core: GET the web root, then log in as a throwaway
user and exercise the array reverse round-trip (store bytes -> read them back
reversed). The array path is the most load-bearing one: it dlopen()s the
runtime-decrypted array.so, so a working round-trip proves nginx + fcgiwrap + the
CGI + the array plugin are all healthy.

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


class ReversaarFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "reversaar-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        up = _client.ping(ip)
        http = CheckResult(name="http", passed=up,
                           detail="GET / -> 200" if up else "web root unreachable")
        if not up:
            return CheckResult(name="reversaar", passed=False, children=[http])

        ok, detail = self._check(ip)
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(name="reversaar",
                           passed=http.passed and checker.passed, children=[http, checker])

    def _check(self, ip: str) -> tuple[bool, str]:
        try:
            with _client.new_client() as c:
                user = "chk" + _rand(10)
                token = _client.login(c, ip, user, _rand(16))

                payload = secrets.token_bytes(48)
                idx = _client.store_array(c, ip, token, payload)
                got = _client.get_array(c, ip, token, idx)
                if got != payload[::-1]:
                    return False, f"array reverse mismatch (got {got[:16]!r}...)"
                return True, "login + array reverse round-trip OK"
        except (_client.ClientError, httpx.HTTPError, UnicodeError) as e:
            return False, f"protocol error: {type(e).__name__}: {e}"
