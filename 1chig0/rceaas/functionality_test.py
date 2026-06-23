"""FunctionalityTest for rceaas.

Logs in as a throwaway user and exercises the core jail shell the way the
upstream saarCTF checker does, condensed to what proves the service works:
mkdir/dir, echo-to-file/type round-trip, and copy. Uses only in-jail paths.

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

_ALNUM = string.ascii_uppercase + string.digits


def _rand(n: int) -> str:
    return "".join(secrets.choice(_ALNUM) for _ in range(n))


class RceaasFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "rceaas-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        conn = _client.connect(_net.resolve(target))
        tcp = CheckResult(name="tcp", passed=conn is not None,
                          detail="connected" if conn else "connect failed")
        if conn is None:
            return CheckResult(name="rceaas", passed=False, children=[tcp])

        ok, detail = self._check(conn)
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(name="rceaas",
                           passed=tcp.passed and checker.passed, children=[tcp, checker])

    def _check(self, conn) -> tuple[bool, str]:
        try:
            _client.login(conn, "chk" + _rand(12), _rand(16))

            d = _rand(12)
            _client.cmd(conn, f"mkdir {d}")
            if d not in _client.cmd(conn, "dir"):
                return False, "mkdir/dir failed"

            marker = _rand(24)
            fname = _rand(8)
            _client.cmd(conn, f"echo {marker} > {fname}")
            if marker not in _client.cmd(conn, f"type {fname}"):
                return False, "echo>file / type round-trip failed"

            cp = _rand(8)
            _client.cmd(conn, f"copy {fname} {cp}")
            if marker not in _client.cmd(conn, f"type {cp}"):
                return False, "copy round-trip failed"

            return True, "login/mkdir/dir/echo/type/copy round-trip OK"
        except (_client.ClientError, nclib.NetcatError, UnicodeError,
                OSError, EOFError) as e:
            return False, f"protocol error: {type(e).__name__}: {e}"
        finally:
            conn.close()
