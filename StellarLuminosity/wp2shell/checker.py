"""CHECKER for wp2shell -- the deep gameplay-correctness probe, run in the
Health Poller over the network (never execs into prod, so root-on-prod cannot
tamper with it).

Exercises NORMAL WordPress REST API behavior only. It does not depend on the
vulnerability staying open, and every assertion here is expected to keep
passing after the intended defense is applied:

  * public_posts   -- GET /wp-json/wp/v2/posts is reachable, unauthenticated,
                      and returns the seeded published post.
  * array_filter   -- the SAME endpoint with author_exclude passed as a
                      normal array still returns 200 with a well-formed list.
  * batch_alive    -- POST /wp-json/batch/v1 with a single benign sub-request
                      answers normally.
  * homepage       -- GET / renders real WordPress markup, not a stub.

Deliberately unauthenticated throughout: WordPress default REST API needs no
credential to list published posts, so there is no admin/app-password channel
here for an attacker to replay against the opponent.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


@dataclass(frozen=True)
class _Response:
    status_code: int
    text: str

    def json(self):
        return json.loads(self.text)


def _request(
    method: str,
    url: str,
    *,
    params: dict[str, str] | None = None,
    json_body: dict | None = None,
    timeout: float = 10.0,
) -> _Response:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"

    data = None
    headers = {}
    if json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return _Response(status_code=r.status, text=body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return _Response(status_code=e.code, text=body)


class Wp2ShellChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "wp2shell-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = f"http://{target.host}:{target.ports['service']}"
        children = [
            self._check_public_posts(base),
            self._check_array_filter(base),
            self._check_batch_alive(base),
            self._check_homepage(base),
        ]

        return CheckResult(
            name="checker",
            passed=all(child.passed for child in children),
            children=children,
        )

    def _check_public_posts(self, base: str) -> CheckResult:
        try:
            r = _request("GET", f"{base}/wp-json/wp/v2/posts")
            body = r.json() if r.status_code == 200 else None
            ok = r.status_code == 200 and isinstance(body, list) and len(body) >= 1
            return CheckResult(
                name="public_posts",
                passed=ok,
                detail=(
                    f"GET /wp/v2/posts -> {r.status_code}, "
                    f"{len(body) if isinstance(body, list) else 'n/a'} posts"
                ),
            )
        except (OSError, ValueError) as e:
            return CheckResult(
                name="public_posts",
                passed=False,
                detail=f"{type(e).__name__}: {e}"[:200],
            )

    def _check_array_filter(self, base: str) -> CheckResult:
        try:
            r = _request(
                "GET",
                f"{base}/wp-json/wp/v2/posts",
                params={"author_exclude[]": "999999"},
            )
            ok = r.status_code == 200 and isinstance(r.json(), list)
            return CheckResult(
                name="array_filter",
                passed=ok,
                detail=f"GET /wp/v2/posts?author_exclude[]=999999 -> {r.status_code}",
            )
        except (OSError, ValueError) as e:
            return CheckResult(
                name="array_filter",
                passed=False,
                detail=f"{type(e).__name__}: {e}"[:200],
            )

    def _check_batch_alive(self, base: str) -> CheckResult:
        payload = {
            "requests": [
                {
                    "path": "/wp/v2/posts",
                    "method": "POST",
                    "body": {"title": "healthcheck"},
                }
            ]
        }
        try:
            r = _request("POST", f"{base}/wp-json/batch/v1", json_body=payload)
            ok = r.status_code in (200, 207)
            return CheckResult(
                name="batch_alive",
                passed=ok,
                detail=f"POST /batch/v1 benign -> {r.status_code}",
            )
        except OSError as e:
            return CheckResult(
                name="batch_alive",
                passed=False,
                detail=f"{type(e).__name__}: {e}"[:200],
            )

    def _check_homepage(self, base: str) -> CheckResult:
        try:
            r = _request("GET", base)
            markers = ("wp-content" in r.text) or ("WordPress" in r.text)
            ok = r.status_code == 200 and markers
            return CheckResult(
                name="homepage",
                passed=ok,
                detail=f"GET / -> {r.status_code}, wp markers: {markers}",
            )
        except OSError as e:
            return CheckResult(
                name="homepage",
                passed=False,
                detail=f"{type(e).__name__}: {e}"[:200],
            )
