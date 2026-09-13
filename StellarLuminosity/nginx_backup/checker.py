"""Network CHECKER for nginx-backup.

This runs in the health poller, not inside prod. It checks that the reverse
proxy still serves normal nginx-ui behavior after a defender edits proxy.conf:
the SPA entry point loads, at least one frontend asset is reachable, and a
protected API route still reaches nginx-ui instead of being blocked by a broad
proxy rule.
"""

from __future__ import annotations

import html
import re
import urllib.error
import urllib.parse
import urllib.request

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

_TIMEOUT = 8
_ASSET_RE = re.compile(
    r"""(?:src|href)=["']([^"']+\.(?:js|css)(?:\?[^"']*)?)["']""",
    re.IGNORECASE,
)



def _open(url: str) -> tuple[int, bytes, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "CyberArena-checker"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, resp.read(), resp.geturl()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.geturl()


def _asset_urls(base: str, body: bytes) -> list[str]:
    text = body.decode("utf-8", "replace")
    urls: list[str] = []
    for raw in _ASSET_RE.findall(text):
        url = urllib.parse.urljoin(base + "/", html.unescape(raw))
        if url not in urls:
            urls.append(url)
    return urls


def _looks_like_proxy_block(body: bytes) -> bool:
    text = body[:4096].lower()
    return b"<html" in text and b"nginx" in text and b"forbidden" in text


class NginxBackupChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nginx-backup-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base = f"http://{target.host}:{target.ports['service']}"

        home_status, home_body, home_url = _open(base + "/")
        if home_status < 200 or home_status >= 400:
            return CheckResult(
                name="checker",
                passed=False,
                detail=f"GET / returned HTTP {home_status}",
            )
        if b"<html" not in home_body[:4096].lower():
            return CheckResult(
                name="checker",
                passed=False,
                detail="GET / did not look like an HTML UI entry point",
            )

        assets = _asset_urls(home_url.rsplit("/", 1)[0], home_body)
        if not assets:
            return CheckResult(
                name="checker",
                passed=False,
                detail="GET / did not reference any js/css assets",
            )
        asset_status, asset_body, asset_url = _open(assets[0])
        if asset_status < 200 or asset_status >= 400 or len(asset_body) < 64:
            return CheckResult(
                name="checker",
                passed=False,
                detail=f"asset {asset_url} returned HTTP {asset_status}",
            )

        api_status, api_body, _ = _open(base + "/api/settings")
        if api_status in (401, 405) or (
            api_status == 403 and not _looks_like_proxy_block(api_body)
        ):
            return CheckResult(
                name="checker",
                passed=True,
                detail=(
                    f"UI and static asset load; protected API reaches backend "
                    f"(HTTP {api_status})"
                ),
            )
        return CheckResult(
            name="checker",
            passed=False,
            detail=(
                "GET /api/settings should reach nginx-ui and fail as an "
                f"unauthenticated API request; got HTTP {api_status}"
            ),
        )
