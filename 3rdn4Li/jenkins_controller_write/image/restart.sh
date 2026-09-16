#!/usr/bin/env bash
set -euo pipefail

/arena/stop.sh
/arena/rebuild.sh
exec /arena/start.sh
