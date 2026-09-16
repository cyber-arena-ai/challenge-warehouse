"""Small stdlib OpenTSDB client used only by external health probes."""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request


_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_JSON_ACCEPTS = ("application/json", "application/json, */*;q=0.8", "*/*")
_HTML_ACCEPTS = (
    "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "text/html,*/*;q=0.8",
    "*/*",
)
_PNG_ACCEPTS = (
    "image/png,image/*;q=0.9,*/*;q=0.8",
    "image/png,*/*;q=0.8",
    "*/*",
)


def _user_agent() -> str:
    """Return one plausible participant client with a randomized version."""
    family = secrets.randbelow(4)
    if family == 0:
        return f"curl/8.{secrets.randbelow(15)}.{secrets.randbelow(4)}"
    if family == 1:
        return (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            f"Chrome/{120 + secrets.randbelow(26)}.0."
            f"{5000 + secrets.randbelow(3000)}.{secrets.randbelow(200)} "
            "Safari/537.36"
        )
    if family == 2:
        return (
            f"python-requests/2.{25 + secrets.randbelow(9)}."
            f"{secrets.randbelow(6)}"
        )
    return f"Wget/1.{19 + secrets.randbelow(7)}.{secrets.randbelow(10)}"


def _accepts(path: str) -> tuple[str, ...]:
    if path == "/":
        return _HTML_ACCEPTS
    if path.startswith("/q?") and path.endswith("&png"):
        return _PNG_ACCEPTS
    return _JSON_ACCEPTS


class OpenTSDBClient:
    def __init__(self, host: str, port: int, token: str | None = None):
        self.base = f"http://{host}:{port}"
        self.token = token
        self.user_agent = _user_agent()
        self.accept_headers = {
            accepts: secrets.choice(accepts)
            for accepts in (_JSON_ACCEPTS, _HTML_ACCEPTS, _PNG_ACCEPTS)
        }

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict | None = None,
        timeout: float = 4.0,
    ) -> tuple[int, str]:
        status, body = self.request_bytes(
            path,
            method=method,
            payload=payload,
            timeout=timeout,
        )
        return status, body.decode(errors="replace")

    def request_bytes(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict | None = None,
        timeout: float = 4.0,
    ) -> tuple[int, bytes]:
        data = None
        headers = {
            "User-Agent": self.user_agent,
            "Accept": self.accept_headers[_accepts(path)],
        }
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
                body = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise ValueError("OpenTSDB response exceeded 8 MiB")
                return response.status, body
        except urllib.error.HTTPError as error:
            body = error.read(_MAX_RESPONSE_BYTES + 1)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise ValueError("OpenTSDB error response exceeded 8 MiB")
            return error.code, body

    def put(
        self,
        metric: str,
        tag: str,
        value: int,
        *,
        tag_key: str = "probe",
        timestamp: int | None = None,
    ) -> tuple[int, str, int]:
        timestamp = int(time.time()) if timestamp is None else timestamp
        status, body = self.request(
            "/api/put?details",
            method="POST",
            payload={
                "metric": metric,
                "timestamp": timestamp,
                "value": value,
                "tags": {tag_key: tag},
            },
        )
        return status, body, timestamp

    @staticmethod
    def _metric_query(metric: str, tag: str, tag_key: str) -> str:
        return f"sum:{metric}{{{tag_key}={tag}}}"

    def query(
        self,
        metric: str,
        tag: str,
        timestamp: int,
        *,
        tag_key: str = "probe",
    ) -> tuple[int, str]:
        params = urllib.parse.urlencode(
            {
                "start": str(timestamp - 60),
                "end": str(timestamp + 60),
                "m": self._metric_query(metric, tag, tag_key),
            }
        )
        return self.request(f"/api/query?{params}")

    def graph(
        self,
        metric: str,
        tag: str,
        timestamp: int,
        *,
        tag_key: str = "probe",
        legend: str = "left",
        dimensions: str = "800x600",
    ) -> tuple[int, str]:
        params = self._graph_params(
            metric,
            tag,
            timestamp,
            tag_key=tag_key,
            legend=legend,
            dimensions=dimensions,
        )
        return self.request(f"/q?{params}&json", timeout=20.0)

    def graph_png(
        self,
        metric: str,
        tag: str,
        timestamp: int,
        *,
        tag_key: str = "probe",
        legend: str = "left",
        dimensions: str = "800x600",
    ) -> tuple[int, bytes]:
        params = self._graph_params(
            metric,
            tag,
            timestamp,
            tag_key=tag_key,
            legend=legend,
            dimensions=dimensions,
        )
        return self.request_bytes(f"/q?{params}&png", timeout=20.0)

    def _graph_params(
        self,
        metric: str,
        tag: str,
        timestamp: int,
        *,
        tag_key: str,
        legend: str,
        dimensions: str,
    ) -> str:
        params = urllib.parse.urlencode(
            {
                "start": str(timestamp - 60),
                "end": str(timestamp + 60),
                "m": self._metric_query(metric, tag, tag_key),
                "o": "axis x1y2",
                "key": legend,
                "wxh": dimensions,
                "nocache": "1",
            }
        )
        return params
