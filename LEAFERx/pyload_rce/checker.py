"""CHECKER for pyload-rce — run in the Health Poller over the network (never
execs into prod), per orche #103 "CHECKER out of prod's trust boundary".

Authenticates against pyLoad and calls /api/statusServer to verify the service
is fully functional — not just that a web page loads. This supersedes the old
baked `image/checker_impl.py` (readable/overwritable by the root defender) and
the `python3 /arena/checker_impl.py` wrapper in `image/checker.sh`.

Auth strategy (handles both CVE-pinned 0.5.0b3.dev79 and patched upstream):
  1. Try POST /api/login (json-api login, works on 0.5.0b3.dev79).
  2. If that returns 404 "Obsolete API" (newer builds removed this endpoint),
     fall back to web-form login: GET /login, extract the CSRF token, POST /login.
  The session cookie carries through to the /api/statusServer call.

Credentials: pyload/pyload (default admin created by headless config-gen at
image build time). Uses only Python stdlib — no extra pip in the poller.
"""

from __future__ import annotations

import http.cookiejar
import ipaddress
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

USER = "pyload"
PASS = "pyload"
REQUIRED_KEYS = {"pause", "active", "queue", "total", "speed", "download"}
_TIMEOUT = 10


def _resolve_host(target: VulboxTarget) -> str:
    """A routable IP for the vulbox. `target.host` is the prod container name;
    turn it into a bridge IP via `docker inspect` (mirrors btx/_net.resolve). An
    already-IP host, or an inspect failure, is used as-is."""
    host = target.host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", host],
            capture_output=True, text=True, timeout=5,
        ).stdout.split()
        if out:
            return out[0]
    except Exception:
        pass
    return host


def _make_opener() -> urllib.request.OpenerDirector:
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def _auth_api_login(opener: urllib.request.OpenerDirector, base: str) -> bool:
    """POST /api/login (CVE-pinned build). True on success; False on 404 (newer
    build → caller falls back to web login). Other HTTP errors propagate."""
    data = urllib.parse.urlencode({"username": USER, "password": PASS}).encode()
    req = urllib.request.Request(base + "/api/login", data=data, method="POST")
    try:
        resp = opener.open(req, timeout=_TIMEOUT)
        return bool(json.loads(resp.read()).get("authenticated"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def _auth_web_login(opener: urllib.request.OpenerDirector, base: str) -> tuple[bool, str]:
    """Web-form login with CSRF extraction (newer builds). Returns (ok, detail)."""
    try:
        body = opener.open(base + "/login", timeout=_TIMEOUT).read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return False, f"GET /login error: {e}"
    tokens = re.findall(r'name="csrf_token"[^>]*value="([^"]+)"', body)
    if not tokens:
        return False, "GET /login: no csrf_token field in login form"
    data = urllib.parse.urlencode({
        "username": USER, "password": PASS, "do": "login", "csrf_token": tokens[0],
    }).encode()
    req = urllib.request.Request(base + "/login", data=data, method="POST")
    try:
        resp = opener.open(req, timeout=_TIMEOUT)
    except urllib.error.HTTPError as e:
        return False, f"POST /login error: {e.code} {e.read()[:200]!r}"
    # Success: pyLoad redirects to /dashboard (old checker's criterion, verbatim).
    if "/dashboard" in resp.url or resp.status == 200:
        return True, "web-form login"
    return False, f"POST /login: not authenticated (status={resp.status})"


def _status_server(opener: urllib.request.OpenerDirector, base: str) -> tuple[dict | None, str]:
    """Call /api/statusServer (GET on newer builds, POST on older). Returns
    (parsed_json_or_None, detail)."""
    for method in ("GET", "POST"):
        req = urllib.request.Request(
            base + "/api/statusServer",
            data=(b"" if method == "POST" else None), method=method,
        )
        try:
            return json.loads(opener.open(req, timeout=_TIMEOUT).read()), method
        except urllib.error.HTTPError as e:
            if e.code in (405, 401):
                continue
            return None, f"{method} /api/statusServer error: {e.code} {e.read()[:200]!r}"
        except Exception as e:  # noqa: BLE001
            return None, f"{method} /api/statusServer error: {e}"
    return None, "no method (GET/POST) succeeded"


class PyloadChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "pyload-rce-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = f"http://{_resolve_host(target)}:{target.ports['web']}"

        # Step 1: authenticate (api/login, else web-form login on a fresh jar).
        opener = _make_opener()
        try:
            authenticated = _auth_api_login(opener, base)
        except urllib.error.HTTPError as e:
            return CheckResult(name="checker", passed=False,
                               detail=f"POST /api/login: {e.code} {e.read()[:200]!r}")
        except Exception as e:  # noqa: BLE001
            return CheckResult(name="checker", passed=False, detail=f"POST /api/login: {e}")

        if not authenticated:
            opener = _make_opener()  # fresh cookie jar for the web-form path
            authenticated, detail = _auth_web_login(opener, base)
            if not authenticated:
                # Mirrors the old checker's "failed with both api/login and
                # web-form login" verdict, but keeps the specific web-login reason.
                return CheckResult(name="checker", passed=False,
                                   detail=f"authentication failed (api/login 404 → {detail})")

        # Step 2: /api/statusServer must answer with the expected keys.
        status, detail = _status_server(opener, base)
        if status is None:
            return CheckResult(name="checker", passed=False, detail=f"statusServer: {detail}")
        missing = REQUIRED_KEYS - set(status.keys())
        if missing:
            return CheckResult(name="checker", passed=False,
                               detail=f"statusServer missing keys {missing}, got {status}")

        return CheckResult(
            name="checker", passed=True,
            detail=(f"statusServer active={status['active']} "
                    f"queue={status['queue']} download={status['download']}"),
        )
