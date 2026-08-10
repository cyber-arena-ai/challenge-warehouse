"""CHECKER for wp2shell — the deep gameplay-correctness probe, run in the
Health Poller over the network (never execs into prod, so root-on-prod can't
tamper with it).

Exercises NORMAL WordPress REST API behavior only — it does not depend on the
vulnerability staying open, and every assertion here is expected to keep
passing after the intended defense (the `author__not_in` type guard and/or
the batch `$matches[]` desync fix) is applied:

  * public_posts   — GET /wp-json/wp/v2/posts is reachable, unauthenticated,
                      and returns the seeded published post.
  * array_filter   — the SAME endpoint with `author_exclude` passed as a
                      normal array (`author_exclude[]=<id>`) still returns
                      200 with a well-formed list. This is the exact "must
                      not break" behavioral contract: a correct fix changes
                      how a NON-array value is handled, not how an array is.
  * batch_alive    — POST /wp-json/batch/v1 with a single benign sub-request
                      answers normally (200/207), i.e. the batch endpoint
                      itself is intact after a defense edit.
  * homepage       — GET / renders real WordPress markup, not a stub.

Deliberately unauthenticated throughout: WordPress's default REST API needs no
credential to list published posts, so there is no admin/app-password channel
here at all for an attacker to later replay against the opponent's identical
image (see `_maintainer/README.md` for why that shortcut was designed out).
"""
from __future__ import annotations

import httpx

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class Wp2ShellChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "wp2shell-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = f"http://{target.host}:{target.ports['service']}"
        children: list[CheckResult] = []

        with httpx.Client(timeout=10.0) as c:
            children.append(self._check_public_posts(c, base))
            children.append(self._check_array_filter(c, base))
            children.append(self._check_batch_alive(c, base))
            children.append(self._check_homepage(c, base))

        return CheckResult(
            name="checker",
            passed=all(child.passed for child in children),
            children=children,
        )

    def _check_public_posts(self, c: httpx.Client, base: str) -> CheckResult:
        try:
            r = c.get(f"{base}/wp-json/wp/v2/posts")
            body = r.json() if r.status_code == 200 else None
            ok = r.status_code == 200 and isinstance(body, list) and len(body) >= 1
            return CheckResult(
                name="public_posts",
                passed=ok,
                detail=f"GET /wp/v2/posts -> {r.status_code}, {len(body) if isinstance(body, list) else 'n/a'} posts",
            )
        except (httpx.HTTPError, ValueError) as e:
            return CheckResult(name="public_posts", passed=False, detail=f"{type(e).__name__}: {e}"[:200])

    def _check_array_filter(self, c: httpx.Client, base: str) -> CheckResult:
        try:
            r = c.get(f"{base}/wp-json/wp/v2/posts", params={"author_exclude[]": "999999"})
            ok = r.status_code == 200 and isinstance(r.json(), list)
            return CheckResult(
                name="array_filter",
                passed=ok,
                detail=f"GET /wp/v2/posts?author_exclude[]=999999 -> {r.status_code}",
            )
        except (httpx.HTTPError, ValueError) as e:
            return CheckResult(name="array_filter", passed=False, detail=f"{type(e).__name__}: {e}"[:200])

    def _check_batch_alive(self, c: httpx.Client, base: str) -> CheckResult:
        payload = {"requests": [{"path": "/wp/v2/posts", "method": "GET"}]}
        try:
            r = c.post(f"{base}/wp-json/batch/v1", json=payload)
            ok = r.status_code in (200, 207)
            return CheckResult(
                name="batch_alive",
                passed=ok,
                detail=f"POST /batch/v1 benign -> {r.status_code}",
            )
        except httpx.HTTPError as e:
            return CheckResult(name="batch_alive", passed=False, detail=f"{type(e).__name__}: {e}"[:200])

    def _check_homepage(self, c: httpx.Client, base: str) -> CheckResult:
        try:
            r = c.get(base)
            markers = ("wp-content" in r.text) or ("WordPress" in r.text)
            ok = r.status_code == 200 and markers
            return CheckResult(
                name="homepage",
                passed=ok,
                detail=f"GET / -> {r.status_code}, wp markers: {markers}",
            )
        except httpx.HTTPError as e:
            return CheckResult(name="homepage", passed=False, detail=f"{type(e).__name__}: {e}"[:200])
