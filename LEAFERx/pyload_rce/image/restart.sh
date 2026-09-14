#!/usr/bin/env bash

set -euo pipefail

PORT=8000
SOURCE=/srv/challenge/pyload
DATA=/srv/pyload
PIDFILE=/srv/pyload/pyload.pid
LOG=/var/log/pyload.stdout

# Restarts must not interleave: stop_worker retires the whole service account,
# so a concurrent run would tear down the generation this one just started and
# turn its restart into a spurious failure. /var/lib/pyload-arena is root-only
# (0700), so the service account cannot open the lock and stall restarts by
# holding it. The wait is generous, not a guarantee: chown -R below is unbounded
# over a directory the service account can fill.
exec 9>/var/lib/pyload-arena/restart.lock
flock -w 900 9 || { echo "another restart is still running" >&2; exit 1; }

port_up() {
    timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/${PORT}" 2>/dev/null
}

# A compromised service account can forge both ${PIDFILE} and the worker's argv,
# so neither identifies the worker. Retire the whole account instead: uid 1000
# exists only to run pyLoad, and -u matches effective uid, so the setuid-root
# proof helper is untouched. Leaving any survivor would also let it win the bind
# race against the generation started below.
stop_worker() {
    pkill -TERM -u pyload 2>/dev/null || true
    for _ in $(seq 1 40); do
        pgrep -u pyload >/dev/null 2>&1 || break
        sleep 0.1
    done
    for _ in $(seq 1 40); do
        pgrep -u pyload >/dev/null 2>&1 || port_up || break
        pkill -KILL -u pyload 2>/dev/null || true
        sleep 0.1
    done
    rm -f "${PIDFILE}"
    if pgrep -u pyload >/dev/null 2>&1 || port_up; then
        echo "teardown failed: service account still active on port ${PORT}" >&2
        return 1
    fi
}

# Retire the old generation before any defender-controlled validation can hang
# or fail. Repeat teardown afterward because an import can start child work;
# defender code is imported as the service account so that work is attributable.
stop_worker
validation_failed=0
if ! PYTHONPATH="${SOURCE}/src" timeout 120 python -m compileall -q -f "${SOURCE}/src/pyload" \
    || ! runuser -u pyload -- timeout 120 env \
        HOME=/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${SOURCE}/src" \
        python -c \
        "import pyload.webui.app.blueprints.cnl_blueprint; import pyload.core.utils.misc"
then
    validation_failed=1
fi
stop_worker
if [ "${validation_failed}" -ne 0 ]; then
    echo "edited source failed validation; pyLoad stopped" >&2
    exit 1
fi

chown -R pyload:pyload "${DATA}"
# The service account owns /tmp/pyLoad inside a world-writable /tmp, so it can
# replace the directory with a symlink. Left in place that fails every later
# mkdir -- after the teardown above -- and permanently denies the defender a
# restart. Discard whatever is there first; rm does not follow the final symlink.
rm -rf /tmp/pyLoad
mkdir -p /tmp/pyLoad "$(dirname "${LOG}")"
chown pyload:pyload /tmp/pyLoad

nohup runuser -u pyload -- env \
    HOME=/tmp \
    PYTHONPATH="${SOURCE}/src" \
    pyload --userdir "${DATA}/u" --storagedir "${DATA}/s" \
        --tempdir "${DATA}/t" --pidfile "${PIDFILE}" \
    9>&- >"${LOG}" 2>&1 &
worker=$!

worker_alive() {
    local state
    state=$(ps -o state= -p "${worker}" 2>/dev/null) || return 1
    [ -n "${state}" ] && [ "${state}" != "Z" ]
}

# The port is attributable to this generation only because stop_worker returns
# just once no service-account process survives and nothing answers, so nothing
# of the attacker's is left to bind ahead of the worker.
for _ in $(seq 1 90); do
    if ! worker_alive; then
        echo "pyLoad exited during start" >&2
        tail -n 80 "${LOG}" >&2 || true
        stop_worker
        exit 1
    fi
    if port_up; then
        echo "pyLoad server ready on port ${PORT}"
        exit 0
    fi
    sleep 0.5
done

echo "pyLoad failed to become ready" >&2
tail -n 80 "${LOG}" >&2 || true
stop_worker
exit 1
