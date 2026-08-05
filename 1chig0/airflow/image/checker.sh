#!/usr/bin/env bash
# CHECKER probe: the airflow API server must answer 200 on /api/v2/version (:8080).
# This is the minimal liveness gate; the full functionality contract (redaction,
# authorized materialize, protected-DAG denial) is enforced by functionality_test.
set -e
PORT=8080
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/api/v2/version" || true)
[ "$code" = "200" ]
