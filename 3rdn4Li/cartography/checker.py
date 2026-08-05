"""CHECKER for faust-cartography — the deep gameplay round-trip, run in the
Health Poller over the network (never execs into prod).

Inlines the upstream `check_service`: create + fill a sector with a random
payload, read back 5 random substrings and verify them, then save + reload the
sector. This supersedes the old (weaker, menu-prompt-only) image/checker.sh.
"""
from __future__ import annotations

import logging
import random

import nclib

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from . import _client, _net

log = logging.getLogger(__name__)

_VALUES = ["Normal", "Critical", "Needs investigation"]


def _random_sensor_data():
    width = random.randint(10, 20)
    height = random.randint(10, 20)
    return ("Sector " + hex(random.randint(0, 256)) + ";"
            + "Width: " + str(width) + ";"
            + "Height: " + str(height) + ";"
            + "Status: " + random.choice(_VALUES) + ";"
            + "Height data: "
            + "".join(chr(random.randint(ord("a"), ord("z"))) for _ in range(width * height)))


class CartographyChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "faust-cartography-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        conn = _client.connect(_net.resolve(target))
        if conn is None:
            return CheckResult(name="checker", passed=False, detail="connect failed")
        ok, detail = self._check(conn)
        return CheckResult(name="checker", passed=ok, detail=detail[-200:])

    def _check(self, conn) -> tuple[bool, str]:
        try:
            if random.choice([True, False]):
                payload = _random_sensor_data()
            else:
                size = random.randint(10, 100)
                payload = "".join(chr(random.randint(ord("a"), ord("z"))) for _ in range(size))

            _client.new_sector(conn, len(payload))
            _client.fill_sector(conn, 0, payload)
            for _ in range(5):
                start = random.randint(0, len(payload) - 1)
                length = random.randint(1, len(payload) - start)
                expected = payload[start:start + length]
                if _client.read_sector(conn, start, length) != expected:
                    return False, "substring read mismatch"
            sector = _client.save_sector(conn)
            if not _client.load_sector(conn, sector):
                return False, "failed to reload just-saved sector"
            return True, "create/fill/read/save/load round-trip OK"
        except (_client.ClientError, nclib.NetcatError, UnicodeDecodeError,
                OSError, EOFError) as e:
            # OSError covers BrokenPipeError/ConnectionReset when a broken
            # service drops the socket mid-protocol — a failed leaf, not a raise.
            return False, f"protocol error: {type(e).__name__}: {e}"
        finally:
            conn.close()
