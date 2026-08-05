"""CHECKER for faust-treasury — the deep gameplay round-trip, run in the Health
Poller over the network (never execs into prod).

Inlines the upstream `check_service`: add a location, view it back and verify
the description, exercise the (stubbed) update feature, and sometimes the logs
gate. This supersedes the old (weaker, connect-banner-only) image/checker.sh.
"""
from __future__ import annotations

import logging
import random

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)


class TreasuryChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-treasury-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        ok, detail = self._check(ip)
        return CheckResult(name="checker", passed=ok, detail=detail[-200:])

    def _check(self, ip) -> tuple[bool, str]:
        new_loc = _client.generate_random_string(59)
        new_desc = _client.generate_random_string(80)
        try:
            ret = _client.add_treasure(ip, new_loc, new_desc)
            while ret == 2:
                new_loc = _client.generate_random_string(59)
                ret = _client.add_treasure(ip, new_loc, new_desc)
            if ret != 0:
                return False, f"add_treasure returned {ret}"

            val = _client.view_treasure(ip, new_loc)
            if val is None:
                return False, "view_treasure failed"
            if val.decode() != new_desc:
                return False, "view_treasure returned wrong value"

            if not _client.update_location(ip):
                return False, "update_location failed"
            if random.choice([1, 2]) == 2 and not _client.print_logs(ip):
                return False, "print_logs gate failed"
        except ConnectionRefusedError:
            return False, "connect failed"
        except Exception as e:  # noqa: BLE001
            # A broken service drops the connection mid-protocol — pwntools
            # raises EOFError there. tcp stayed up, so this is a failed checker
            # leaf, not "connect failed" and not an infra raise.
            return False, f"protocol error: {type(e).__name__}: {e}"
        return True, "add/view/update round-trip OK"
