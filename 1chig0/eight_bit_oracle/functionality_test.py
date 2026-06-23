"""FunctionalityTest for 8-bit-oracle.

Exercises the public contract the way the upstream saarCTF checker does, condensed
to what proves the service (and its MariaDB-backed review store + RSA crypto) work:
MSG, STATS shape, and a full REVIEW -> CHALLENGE -> DECRYPT -> GETREVIEW round-trip
that reads back exactly what was written.

CheckResult tree: tcp + checker.
"""
from __future__ import annotations

import logging
import re
import secrets

import nclib

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)

_STATS_RE = re.compile(r"STATS [0-9a-fA-F]{1,16} \d+ \d+")


class EightBitOracleFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "8-bit-oracle-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        conn = _client.connect(_net.resolve(target))
        tcp = CheckResult(name="tcp", passed=conn is not None,
                          detail="connected" if conn else "connect failed")
        if conn is None:
            return CheckResult(name="8-bit-oracle", passed=False, children=[tcp])

        ok, detail = self._check(conn)
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(name="8-bit-oracle",
                           passed=tcp.passed and checker.passed, children=[tcp, checker])

    def _check(self, conn) -> tuple[bool, str]:
        try:
            # MSG round-trips a random answer.
            msg = _client.request(conn, "MSG hello?")
            if not msg.startswith("MSG "):
                return False, f"MSG failed: {msg[:48]!r}"

            # STATS has the documented shape.
            stats = _client.request(conn, "STATS")
            if not _STATS_RE.match(stats):
                return False, f"STATS malformed: {stats[:48]!r}"

            # Full review round-trip (writes + reads back exactly).
            marker = "chk_" + secrets.token_hex(8)
            rid, key = _client.review(conn, marker)
            ct = _client.get_challenge(conn, rid)
            plain = _client.decrypt(conn, key, ct)
            review = _client.get_review(conn, rid, plain)
            if review != marker:
                return False, f"review round-trip mismatch: {review[:48]!r}"

            return True, "MSG/STATS + REVIEW->CHALLENGE->DECRYPT->GETREVIEW round-trip OK"
        except (_client.ClientError, nclib.NetcatError, ValueError, UnicodeError,
                OSError, EOFError) as e:
            return False, f"protocol error: {type(e).__name__}: {e}"
        finally:
            conn.close()
