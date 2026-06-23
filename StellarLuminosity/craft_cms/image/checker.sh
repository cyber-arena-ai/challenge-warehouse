#!/usr/bin/env bash
# CHECKER-level health probe for craft-cms.
#
# GETs the Craft control-panel login page and verifies the response is genuine
# Craft-rendered HTML (carries the CRAFT_CSRF_TOKEN the app injects), not a
# stub 200 swapped in to cheese the port check. A plain echo/static server
# would not emit Craft's CSRF token field.
#
# Mode 555, root-owned. Exits 0 on pass; stdout/stderr feeds the health detail.

set -e

URL="http://127.0.0.1/index.php?p=admin/login"

RESPONSE=$(curl -sf --max-time 8 "$URL" 2>/dev/null) || {
    echo "checker: admin login endpoint unreachable" >&2
    exit 1
}

if echo "$RESPONSE" | grep -Eqi "CRAFT_CSRF_TOKEN|csrfTokenValue|Craft CMS"; then
    echo "checker: Craft control-panel login served correctly"
    exit 0
else
    echo "checker: login page missing expected Craft markers" >&2
    echo "checker: first 300 chars: ${RESPONSE:0:300}" >&2
    exit 1
fi
