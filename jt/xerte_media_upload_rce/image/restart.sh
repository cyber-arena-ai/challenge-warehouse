#!/usr/bin/env bash
set -u

MODE="${1:-restart}"
ROOT=/srv/challenge/xerte
MANIFEST=/arena/php-manifest
PIDFILE=/run/xerte-apache.pid
LOG=/var/log/xerte-apache.log

if [ "$MODE" != initial ]; then
    # Validate the defender-edited application sources before serving them.
    # Only files shipped by the pinned revision are checked, so uploaded
    # project content can never decide whether a defence may restart.
    list=$(mktemp)
    (cd "$ROOT" && while IFS= read -r rel; do
        [ -f "$rel" ] && printf '%s\n' "$rel"
    done < "$MANIFEST") > "$list"
    # php -l checks one file per process, so fan out rather than batch.
    errors=$(cd "$ROOT" && xargs -a "$list" -d '\n' -r -n 1 -P 4 \
        php -d error_reporting=E_ERROR -l 2>&1 \
        | grep -v -e '^No syntax errors detected' -e '^xargs: ')
    rm -f "$list"
    if [ -n "$errors" ]; then
        echo "PHP syntax check failed:" >&2
        printf '%s\n' "$errors" | head -40 >&2
        exit 1
    fi
    if ! apachectl configtest >/tmp/configtest 2>&1; then
        echo "Apache configuration check failed:" >&2
        head -20 /tmp/configtest >&2
        exit 1
    fi
fi

if [ -s "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE" 2>/dev/null || true)
    if [ -n "${pid:-}" ]; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 40); do
            kill -0 "$pid" 2>/dev/null || break
            sleep .25
        done
        kill -KILL "$pid" 2>/dev/null || true
    fi
fi
pkill -KILL -x apache2 2>/dev/null || true
rm -f /var/run/apache2/apache2.pid

setsid apache2-foreground >>"$LOG" 2>&1 &
echo $! > "$PIDFILE"

for _ in $(seq 1 200); do
    if curl -fsS -o /dev/null --max-time 2 http://127.0.0.1/index.php; then
        echo "Xerte ready (mode=$MODE)"
        exit 0
    fi
    sleep .25
done
echo "Xerte failed to become ready" >&2
tail -20 "$LOG" >&2 2>/dev/null || true
exit 1
