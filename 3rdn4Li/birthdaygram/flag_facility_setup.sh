#!/usr/bin/env bash
# Facility-side deps for this challenge's flag_handler (run at facility image build).
set -euo pipefail
apt-get update
apt-get install -y --no-install-recommends libgl1 libglib2.0-0 libxcb1
rm -rf /var/lib/apt/lists/*

python -m pip install --no-cache-dir requests stegano Pillow numpy wonderwords
