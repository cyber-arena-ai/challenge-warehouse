#!/usr/bin/env bash
# CHECKER for pyload-rce: authenticate then call /api/statusServer and assert
# a sane JSON response.
#
# Auth strategy (handles both CVE-pinned 0.5.0b3.dev79 and patched upstream):
#   1. Try POST /api/login (json-api login, works on 0.5.0b3.dev79).
#   2. If that returns 404 "Obsolete API", fall back to web-form login:
#      GET /login to extract the CSRF token, then POST /login.
#   In both cases the session cookie carries through to the API call.
#
# Credentials: pyload/pyload (default admin created by headless config-gen at
# image build time — deterministic, no runtime mutation needed).
# Uses only Python stdlib (urllib, http.cookiejar, json, re). No extra pip.

set -e

python3 /arena/checker_impl.py
