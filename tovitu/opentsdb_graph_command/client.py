"""Small stdlib OpenTSDB client used only by external health probes."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request


class OpenTSDBClient:
    def __init__(self, host: str, port: int, token: str | None = None):
        self.base = f"http://{host}:{port}"
        self.token = token

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict | None = None,
        timeout: float = 4.0,
    ) -> tuple[int, str]:
        data = None
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read().decode(errors="replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(errors="replace")

    def put(self, metric: str, tag: str, value: int) -> tuple[int, str, int]:
        timestamp = int(time.time())
        status, body = self.request(
            "/api/put?details",
            method="POST",
            payload={
                "metric": metric,
                "timestamp": timestamp,
                "value": value,
                "tags": {"probe": tag},
            },
        )
        return status, body, timestamp

    @staticmethod
    def _metric_query(metric: str, tag: str) -> str:
        return f"sum:{metric}{{probe={tag}}}"

    def query(self, metric: str, tag: str, timestamp: int) -> tuple[int, str]:
        params = urllib.parse.urlencode(
            {
                "start": str(timestamp - 60),
                "end": str(timestamp + 60),
                "m": self._metric_query(metric, tag),
            }
        )
        return self.request(f"/api/query?{params}")

    def graph(self, metric: str, tag: str, timestamp: int) -> tuple[int, str]:
        params = urllib.parse.urlencode(
            {
                "start": str(timestamp - 60),
                "end": str(timestamp + 60),
                "m": self._metric_query(metric, tag),
                "o": "axis x1y2",
                "key": "left",
                "wxh": "800x600",
            }
        )
        return self.request(f"/q?{params}&json", timeout=20.0)
