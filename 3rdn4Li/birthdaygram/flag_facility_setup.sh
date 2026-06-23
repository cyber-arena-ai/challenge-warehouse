#!/usr/bin/env bash
# Facility-side deps for this challenge's flag_handler (run at facility image build).
set -euo pipefail
pip install --no-cache-dir requests stegano
