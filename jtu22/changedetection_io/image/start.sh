#!/usr/bin/env bash
set -euo pipefail

readonly SRC=/srv/challenge/changedetection
readonly DATA=/srv/changedetection/datastore
readonly LOG=/srv/changedetection/changedetection.log
readonly FIXTURE_LOG=/srv/changedetection/fixture.log

pkill -f '[c]hangedetection.py' 2>/dev/null || true
for _ in $(seq 1 15); do
    pgrep -f '[c]hangedetection.py' >/dev/null || break
    sleep 1
done
pkill -9 -f '[c]hangedetection.py' 2>/dev/null || true

runuser -u arena_agent -- env PYTHONPATH="/usr/local:$SRC" /arena/configure.py

if ! pgrep -f '[f]ixture_server.py' >/dev/null; then
    runuser -u arena_agent -- sh -c \
        "nohup /arena/fixture_server.py >'$FIXTURE_LOG' 2>&1 &"
fi

cd "$SRC"
runuser -u arena_agent -- sh -c \
    "nohup env PYTHONPATH='/usr/local:$SRC' FETCH_WORKERS=1 MINIMUM_SECONDS_RECHECK_TIME=0 \
    DISABLE_VERSION_CHECK=true ALLOW_IANA_RESTRICTED_ADDRESSES=true \
    CHECKER_PUBLIC_ENV=changedetection-checker-environment \
    python ./changedetection.py -d '$DATA' -p 5000 >'$LOG' 2>&1 & echo \$!" \
    > /srv/changedetection/backend.pid
pid="$(cat /srv/changedetection/backend.pid)"
echo "changedetection: process started pid=${pid}"

for _ in $(seq 1 120); do
    if ! kill -0 "$pid" 2>/dev/null; then
        break
    fi
    if curl -sf -o /dev/null http://127.0.0.1:5000/ 2>/dev/null; then
        echo "changedetection: service ready on :5000"
        exit 0
    fi
    sleep 1
done

echo "changedetection: service failed to become ready" >&2
tail -n 80 "$LOG" >&2 || true
exit 1
