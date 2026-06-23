"""FunctionalityTest for btx.

Exercises the core register/login/blog round-trip the way the upstream saarCTF
checker does, condensed to what proves the service is alive and correct:
register a fresh user, log in, publish a blog with a random marker as its title
and content, then read it back through the *34 page-number route and confirm
both the title and content come back.

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


def _rand_uid() -> str:
    # digits only, distinct from the fixed flag user; the service sanitises
    # ids to digits anyway.
    return "5" + "".join(secrets.choice(string.digits) for _ in range(8))


class BtxFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "btx-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        ip = _net.resolve(target)
        conn = _client.connect(ip)
        tcp = CheckResult(name="tcp", passed=conn is not None,
                          detail="connected" if conn else "connect failed")
        if conn is None:
            return CheckResult(name="btx", passed=False, children=[tcp])

        ok, detail = self._check(ip, conn)
        checker = CheckResult(name="checker", passed=ok, detail=detail[-200:])
        return CheckResult(name="btx",
                           passed=tcp.passed and checker.passed,
                           children=[tcp, checker])

    def _check(self, ip, conn) -> tuple[bool, str]:
        try:
            uid = _rand_uid()
            pw = _rand(8)
            title = "CHK" + _rand(20)
            content = "BODY" + _rand(20)

            _client.register(conn, uid.encode(), pw.encode())
            conn.close()
            conn = _client.connect(ip)
            if conn is None:
                return False, "reconnect failed after register"
            _client.login(conn, uid.encode(), pw.encode())
            _client.create_blog(conn, title.encode(), content.encode(),
                                b"notes", visibility=b"true")

            data = _client.read_blog_by_pageno(conn, uid.encode(), b"1")
            if title.encode() not in data:
                return False, "blog title missing from *34 page read"
            if content.encode() not in data:
                return False, "blog content missing from *34 page read"
            return True, "register/login/create-blog/read-back round-trip OK"
        except (_client.ClientError, nclib.NetcatError, UnicodeError,
                OSError, EOFError) as e:
            return False, f"protocol error: {type(e).__name__}: {e}"
        finally:
            try:
                conn.close()
            except Exception:
                pass
