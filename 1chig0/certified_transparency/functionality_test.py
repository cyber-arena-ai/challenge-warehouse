"""FunctionalityTest for certified-transparency: http reachability only.

Exercises the shallow reachability leaf across BOTH daemons:

  * http leaf  — log :3000 get-pubkey + get-sth and monitor :3001 get-pubkey
                 all return well-formed responses (service reachable + alive).

The deep register -> get-proof -> claim round-trip (the CHECKER) moved to
`checker.py`, a network probe the Health Poller runs outside prod's trust
boundary.

CheckResult tree: http.
"""
from __future__ import annotations

import logging

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _net
from ._api import Api, ApiError

log = logging.getLogger(__name__)


class CertifiedTransparencyFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "certified-transparency-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service", "monitor")

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        api = Api(ip)
        try:
            ok_http, http_detail = self._check_http(api)
            http = CheckResult(name="http", passed=ok_http, detail=http_detail[-200:])
            return CheckResult(
                name="certified-transparency",
                passed=http.passed,
                children=[http],
            )
        finally:
            api.close()

    def _check_http(self, api: Api) -> tuple[bool, str]:
        try:
            pk_log = api.get_pubkey()
            if len(pk_log) != 32:
                return False, f"log pubkey wrong size {len(pk_log)}"
            sth = api.get_sth()
            if len(sth) < 8 + 15 + 32:
                return False, "sth too short"
            pk_mon = api.get_pubkey(from_monitor=True)
            if pk_mon != pk_log:
                return False, "monitor pubkey != log pubkey"
            return True, "log+monitor pubkey/sth OK"
        except (ApiError, OSError) as e:
            return False, f"http error: {type(e).__name__}: {e}"
