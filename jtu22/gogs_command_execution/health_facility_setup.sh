#!/usr/bin/env bash
set -euo pipefail
apt-get update
apt-get install -y --no-install-recommends git=1:2.47.3-0+deb13u1
rm -rf /var/lib/apt/lists/*
