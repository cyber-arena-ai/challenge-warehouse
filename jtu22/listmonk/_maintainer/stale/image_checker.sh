#!/usr/bin/env bash
# CHECKER probe wrapper: runs the read-only operator query/export functional check.
set -euo pipefail
exec /arena/checker.py
