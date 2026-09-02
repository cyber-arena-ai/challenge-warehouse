#!/usr/bin/env bash
set -euo pipefail

SRC=/srv/challenge/opentsdb
export JAVA_HOME=/opt/java/openjdk
export PATH="${JAVA_HOME}/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# All upstream dependencies were resolved into the materialized source tree at
# image-build time. Removing wget makes the upstream build prefer its cached,
# checksum-verified curl artifacts, matching the accepted Stage 3 lifecycle.
( cd "${SRC}" && ./build.sh )
/arena/start-opentsdb.sh
