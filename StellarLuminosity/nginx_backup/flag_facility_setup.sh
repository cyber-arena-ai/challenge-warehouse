#!/usr/bin/env bash
set -euo pipefail
sed -i \
    -e 's|URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20260824T000000Z|' \
    -e 's|URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/20260824T000000Z|' \
    -e '/Signed-By:/a Check-Valid-Until: no' \
    /etc/apt/sources.list.d/debian.sources
apt-get update
apt-get install -y --allow-downgrades --no-install-recommends openssl=3.5.6-1~deb13u2
apt-get clean
rm -rf /var/lib/apt/lists/*
