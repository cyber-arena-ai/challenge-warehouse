#!/usr/bin/env bash
# Facility-side deps for this challenge's functionality_test (run at facility image build).
set -euo pipefail
python -m pip install --no-cache-dir pwntools
