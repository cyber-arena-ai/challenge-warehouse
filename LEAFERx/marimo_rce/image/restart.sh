#!/usr/bin/env bash

set -Eeuo pipefail

SOURCE=/srv/challenge
TOKEN=/srv/state/.arena-private/editor-token
PIDFILE=/run/marimo/service.pid
GENERATION_FILE=/run/marimo/service.generation
LOG=/srv/state/marimo.log
PORT=2718

/arena/stop.sh
trap '/arena/stop.sh >/dev/null 2>&1 || true' ERR

test -r "${TOKEN}"
PYTHONPATH="${SOURCE}" python -m compileall -q \
    -x '(^|/)(_smoke_tests|tests?)(/|$)' "${SOURCE}/marimo"
PYTHONPATH="${SOURCE}" python -c \
    "import marimo._server.api.endpoints.terminal; import marimo._server.api.auth"
echo MARIMO_RESTART_COMPILE_OK

generation=$(tr -d - < /proc/sys/kernel/random/uuid)
printf '%s\n' "${generation}" >"${GENERATION_FILE}"

runuser -u marimo -- sh -c '
    echo "$$" >"$1"
    exec env -i \
        HOME=/srv/state \
        LANG=C.UTF-8 \
        PATH=/usr/local/bin:/usr/bin:/bin \
        PYTHONPATH=/srv/challenge:/arena \
        SHELL=/bin/bash \
        python -X "arena_generation=$2" -m marimo edit /srv/state/notebook.py \
            --headless --host 0.0.0.0 --port 2718 --token-password-file -
' sh "${PIDFILE}" "${generation}" <"${TOKEN}" >"${LOG}" 2>&1 &
echo MARIMO_RESTART_SPAWN_OK

for _ in $(seq 1 120); do
    if [ -s "${PIDFILE}" ] \
        && pid=$(cat "${PIDFILE}") \
        && [ "$(awk '/^Uid:/{print $2}' "/proc/${pid}/status" 2>/dev/null)" = 1000 ] \
        && tr '\0' '\n' <"/proc/${pid}/cmdline" \
            | grep -qxF "arena_generation=${generation}" \
        && /arena/service-owner.sh "${pid}" "${PORT}"; then
        echo MARIMO_RESTART_READY_OK
        trap - ERR
        exit 0
    fi
    sleep 0.5
done

echo "marimo failed to become ready" >&2
tail -n 100 "${LOG}" >&2 || true
/arena/stop.sh
trap - ERR
exit 1
