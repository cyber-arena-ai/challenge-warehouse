#!/usr/bin/env bash
# CHECKER probe: the reversaar web root must answer 200 on port 7331.
set -e
PORT=7331
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || true)"
if [ "$code" = "200" ]; then
    echo "checker: reversaar GET / -> 200 OK"
    exit 0
fi
echo "checker: reversaar GET / -> ${code:-none}" >&2
exit 1
