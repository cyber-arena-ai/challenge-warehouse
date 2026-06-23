"""pyload-rce CHECKER implementation.

Authenticates against pyLoad and calls /api/statusServer to verify the service
is fully functional — not just that a web page loads.

Auth strategy (handles both CVE-pinned 0.5.0b3.dev79 and patched upstream):
  1. Try POST /api/login (json-api login, works on 0.5.0b3.dev79).
  2. If that returns 404 "Obsolete API" (newer builds removed this endpoint),
     fall back to web-form login: GET /login, extract the CSRF token, POST /login.
  In both cases the session cookie carries through to the /api/statusServer call.

Credentials: pyload/pyload (default admin created by headless config-gen at
image build time — deterministic, no extra build step needed).
"""
import sys
import json
import re
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

BASE = "http://127.0.0.1:8000"
USER = "pyload"
PASS = "pyload"
REQUIRED_KEYS = {"pause", "active", "queue", "total", "speed", "download"}


def fail(msg: str) -> None:
    print(f"CHECKER fail: {msg}", file=sys.stderr)
    sys.exit(1)


def make_opener() -> urllib.request.OpenerDirector:
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def auth_api_login(opener: urllib.request.OpenerDirector) -> bool:
    """Try POST /api/login (CVE-pinned build). Returns True on success."""
    data = urllib.parse.urlencode({"username": USER, "password": PASS}).encode()
    req = urllib.request.Request(BASE + "/api/login", data=data, method="POST")
    try:
        resp = opener.open(req, timeout=10)
        body = json.loads(resp.read())
        return bool(body.get("authenticated"))
    except urllib.error.HTTPError as e:
        # 404 means "Obsolete API" (newer build) — fall through to web login
        if e.code == 404:
            return False
        raise


def auth_web_login(opener: urllib.request.OpenerDirector) -> bool:
    """Fall-back: web-form login with CSRF extraction (newer builds)."""
    # GET /login to obtain the CSRF token from the form
    try:
        resp = opener.open(BASE + "/login", timeout=10)
        body = resp.read().decode("utf-8", "replace")
    except Exception as e:
        fail(f"GET /login error: {e}")
    tokens = re.findall(r'name="csrf_token"[^>]*value="([^"]+)"', body)
    if not tokens:
        fail("GET /login: no csrf_token field found in login form")
    csrf_token = tokens[0]

    # POST /login with credentials + CSRF token
    data = urllib.parse.urlencode({
        "username": USER,
        "password": PASS,
        "do": "login",
        "csrf_token": csrf_token,
    }).encode()
    req = urllib.request.Request(BASE + "/login", data=data, method="POST")
    try:
        resp = opener.open(req, timeout=10)
        # Success: pyLoad redirects to /dashboard
        return "/dashboard" in resp.url or resp.status == 200
    except urllib.error.HTTPError as e:
        fail(f"POST /login error: {e.code} {e.read()[:200]!r}")
    return False


def check() -> None:
    opener = make_opener()

    # Step 1: authenticate
    try:
        authenticated = auth_api_login(opener)
    except urllib.error.HTTPError as e:
        fail(f"POST /api/login unexpected error: {e.code} {e.read()[:200]!r}")
        return
    except Exception as e:
        fail(f"POST /api/login error: {e}")
        return

    if not authenticated:
        # New build — /api/login returns 404; use web-form login
        opener = make_opener()  # fresh cookie jar
        authenticated = auth_web_login(opener)

    if not authenticated:
        fail("authentication failed with both api/login and web-form login")

    # Step 2: call /api/statusServer (GET on newer builds, POST on older)
    status = None
    for method in ("GET", "POST"):
        req = urllib.request.Request(
            BASE + "/api/statusServer",
            data=(b"" if method == "POST" else None),
            method=method,
        )
        try:
            resp = opener.open(req, timeout=10)
            status = json.loads(resp.read())
            break
        except urllib.error.HTTPError as e:
            if e.code in (405, 401):
                continue
            fail(f"{method} /api/statusServer error: {e.code} {e.read()[:200]!r}")
        except Exception as e:
            fail(f"{method} /api/statusServer error: {e}")

    if status is None:
        fail("/api/statusServer: no method (GET/POST) succeeded")

    missing = REQUIRED_KEYS - set(status.keys())
    if missing:
        fail(f"statusServer missing keys {missing}, got: {status}")

    print(
        f"CHECKER ok: pyLoad API statusServer -> "
        f"active={status['active']} queue={status['queue']} download={status['download']}"
    )


if __name__ == "__main__":
    check()
