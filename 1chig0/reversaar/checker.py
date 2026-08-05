"""CHECKER for reversaar — the deep gameplay round-trip, run in the Health Poller
over the network (never execs into prod).

Mirrors the upstream checker's core: log in as a throwaway user and exercise the
array reverse round-trip (store bytes -> read them back reversed). The array path
is the most load-bearing one: it dlopen()s the runtime-decrypted array.so, so a
working round-trip proves nginx + fcgiwrap + the CGI + the array plugin are all
healthy. This supersedes the old (weaker, GET-/-200-only) image/checker.sh.
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


class ReversaarChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "reversaar-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        ok, detail = self._check(ip)
        return CheckResult(name="checker", passed=ok, detail=detail[-200:])

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
