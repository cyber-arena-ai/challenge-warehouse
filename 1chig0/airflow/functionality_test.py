"""Shallow public liveness probe for the Airflow API server."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class AirflowFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "airflow-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        url = f"http://{target.host}:{target.ports['web']}/api/v2/monitor/health"
        try:
            with urllib.request.urlopen(url, timeout=8) as response:
                raw = response.read()
            document = json.loads(raw)
            healthy = response.status == 200 and isinstance(document, dict)
            detail = f"GET /api/v2/monitor/health -> {response.status}"
        except urllib.error.HTTPError as error:
            healthy = False
            detail = f"GET /api/v2/monitor/health -> {error.code}"
        except (OSError, ValueError, json.JSONDecodeError) as error:
            healthy = False
            detail = type(error).__name__
        return CheckResult("protocol", healthy, detail)
