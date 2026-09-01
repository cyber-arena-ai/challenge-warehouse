"""External semantic checker for the legitimate OpenTSDB workflow."""

from __future__ import annotations

import json
import secrets
import time

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from .client import OpenTSDBClient
from .config import SERVICE_PORT, checker_identity


class OpenTSDBChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "opentsdb-graph-command-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        port = target.ports.get("service", SERVICE_PORT)
        try:
            _, token = checker_identity(str(target.meta.get("team_id", "")))
            client = OpenTSDBClient(target.host, port, token)
            nonce = secrets.token_hex(8)
            metric = f"arena.checker.{nonce}"
            value = secrets.randbelow(900_000) + 100_000
            put_status, put_body, timestamp = client.put(metric, nonce, value)
            if put_status != 200 or '"success":1' not in put_body:
                return self._result(False, f"metric put failed: {put_status} {put_body}")

            query_status, query_body, points = 0, "", {}
            for attempt in range(12):
                query_status, query_body = client.query(metric, nonce, timestamp)
                query = json.loads(query_body) if query_status == 200 else []
                points = query[0].get("dps", {}) if isinstance(query, list) and query else {}
                if str(value) in {str(item) for item in points.values()}:
                    break
                if attempt < 11:
                    time.sleep(0.25)
            if str(value) not in {str(item) for item in points.values()}:
                return self._result(
                    False, f"query mismatch: status={query_status} body={query_body}"
                )

            ui_status, ui_body = client.request("/")
            if ui_status != 200 or "OpenTSDB" not in ui_body:
                return self._result(False, f"UI failed: status={ui_status}")

            graph_status, graph_body = client.graph(metric, nonce, timestamp)
            graph = json.loads(graph_body) if graph_status == 200 else {}
            if graph.get("plotted") != 1 or graph.get("points") != 1:
                return self._result(
                    False, f"graph mismatch: status={graph_status} body={graph_body}"
                )
            return self._result(True, "fresh put/query/UI/one-point Gnuplot graph succeeded")
        except (OSError, RuntimeError, ValueError, KeyError, IndexError) as error:
            return self._result(False, f"{type(error).__name__}: {error}")

    @staticmethod
    def _result(passed: bool, detail: str) -> CheckResult:
        return CheckResult(name="checker", passed=passed, detail=detail[-200:])
