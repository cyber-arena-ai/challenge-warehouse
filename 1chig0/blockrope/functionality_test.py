"""FunctionalityTest for blockrope.

Exercises the core account/banking round-trip the way the upstream saarCTF
checker does, but condensed to what proves the service is alive and correct:
register a receiver + sender, transfer a random marker message, then log back
in as the receiver and confirm the transfer shows up in history.

CheckResult tree: tcp + checker.
"""
from __future__ import annotations

import logging
import secrets
import string

import nclib

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)

_ALNUM = string.ascii_letters + string.digits


def _rand(n: int) -> str:
    return "".join(secrets.choice(_ALNUM) for _ in range(n))


class BlockRopeFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "blockrope-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        conn = _client.connect(_net.resolve(target))
        tcp = CheckResult(name="tcp", passed=conn is not None,
                          detail="connected" if conn else "connect failed")
        if conn is None:
            return CheckResult(name="blockrope", passed=False, children=[tcp])

        ok, detail = self._check(conn)
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(name="blockrope",
                           passed=tcp.passed and checker.passed, children=[tcp, checker])

    def _check(self, conn) -> tuple[bool, str]:
        try:
            marker = "chk_" + _rand(24)

            receiver_pw = _rand(12)
            receiver_id = _client.register_random(conn, receiver_pw, _rand(10))
            _client.logout(conn)

            sender_pw = _rand(12)
            _client.register_random(conn, sender_pw, _rand(10))
            _client.send_money(conn, receiver_id, 1.00, marker)
            _client.logout(conn)

            _client.login(conn, receiver_id, receiver_pw)
            data = _client.history(conn)
            if marker not in data:
                return False, "transaction marker missing from receiver history"
            return True, "register/send/login/history round-trip OK"
        except (_client.ClientError, nclib.NetcatError, UnicodeError,
                OSError, EOFError) as e:
            return False, f"protocol error: {type(e).__name__}: {e}"
        finally:
            conn.close()
