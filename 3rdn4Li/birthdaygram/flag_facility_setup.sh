#!/usr/bin/env bash
# Facility-side deps for this challenge's flag_handler (run at facility image build).
set -euo pipefail
apt-get update
apt-get install -y --no-install-recommends libgl1 libglib2.0-0 libxcb1
rm -rf /var/lib/apt/lists/*

# stegano pinned: 3.0.0 changed hide() to encode the message itself (a bytes
# message now raises); the handler passes text, and an unpinned upgrade must
# not be able to change the plant's behaviour again.
python -m pip install --no-cache-dir requests stegano==3.0.0 Pillow numpy wonderwords
