"""Network CHECKER for craft-cms.

Runs from the health-poller, not inside prod. It verifies that Craft still
serves a real control-panel page and that the asset transform action still
accepts a benign transform request. That catches broad defenses that disable
the whole route instead of rejecting only dangerous object configuration.
"""

from __future__ import annotations

import http.cookiejar
import json
import re
import urllib.error
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

_TIMEOUT = 10
_CSRF_RE = re.compile(r'name="CRAFT_CSRF_TOKEN" value="([^"]+)"')
_CRAFT_MARKERS = ("CRAFT_CSRF_TOKEN", "csrfTokenValue", "Craft CMS")
_ACTION_REACHED_MARKERS = (
    "assetscontroller.php",
    "craftcms/cms/src/controllers/assetscontroller",
    "notfoundhttpexception",
)
_BLOCK_MARKERS = (
    "forbidden",
    "method not allowed",
    "route disabled",
    "endpoint disabled",
)


def _make_opener() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _read_response(resp) -> str:
    return resp.read().decode("utf-8", "replace")


def _get_login(opener: urllib.request.OpenerDirector, base: str) -> tuple[bool, str, str | None]:
    try:
        resp = opener.open(base + "/index.php?p=admin/login", timeout=_TIMEOUT)
        body = _read_response(resp)
    except Exception as e:  # noqa: BLE001
        return False, f"login page error: {e}", None

    if resp.status != 200:
        return False, f"login page status={resp.status}", None
    if not any(marker in body for marker in _CRAFT_MARKERS):
        return False, "login page missing Craft markers", None

    match = _CSRF_RE.search(body)
    if not match:
        return False, "login page missing CRAFT_CSRF_TOKEN field", None
    return True, "login page served real Craft HTML", match.group(1)


def _post_transform(
    opener: urllib.request.OpenerDirector,
    base: str,
    csrf: str,
) -> tuple[bool, str]:
    payload = {
        "CRAFT_CSRF_TOKEN": csrf,
        "assetId": "1",
        "handle": {
            "width": 32,
            "height": 32,
            "mode": "crop",
            "format": "jpg",
        },
    }
    req = urllib.request.Request(
        base + "/index.php?p=actions/assets/generate-transform",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf,
        },
    )

    try:
        resp = opener.open(req, timeout=_TIMEOUT)
        body = _read_response(resp)
        status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return False, f"transform request error: {e}"

    sample = " ".join(body.split())[:180]
    lower = sample.lower()
    # The seeded app has no real asset with id 1. On an unmodified service,
    # Craft still routes the request into AssetsController and then returns a
    # Craft/Yii not-found error. That is a pass: it proves the action remains
    # reachable. A broad front-controller block returns before these markers.
    if any(marker in lower for marker in _ACTION_REACHED_MARKERS):
        return True, f"transform action reached: status={status} body={sample!r}"

    if status in (403, 404, 405):
        return False, f"transform route blocked: status={status} body={sample!r}"
    if any(marker in lower for marker in _BLOCK_MARKERS) and status >= 400:
        return False, f"transform route appears disabled: status={status} body={sample!r}"

    # A valid result or validation error also proves the legitimate action was
    # reached and was not stopped by a broad route block.
    if status < 500 or "craft" in lower or "yii" in lower or "asset" in lower:
        return True, f"transform action reached: status={status} body={sample!r}"

    return False, f"unexpected transform response: status={status} body={sample!r}"


class CraftCmsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "craft-cms-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = f"http://{target.host}:{target.ports['service']}"
        opener = _make_opener()

        login_ok, login_detail, csrf = _get_login(opener, base)
        login = CheckResult(name="checker-login", passed=login_ok, detail=login_detail)
        if not login_ok or csrf is None:
            transform = CheckResult(
                name="checker-transform",
                passed=False,
                detail="skipped; login/CSRF check failed",
            )
        else:
            ok, detail = _post_transform(opener, base, csrf)
            transform = CheckResult(name="checker-transform", passed=ok, detail=detail)

        return CheckResult(
            name="checker",
            passed=login.passed and transform.passed,
            children=[login, transform],
        )
