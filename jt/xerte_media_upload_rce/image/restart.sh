#!/usr/bin/env bash
set -eu

MODE="${1:-restart}"
SOURCE_ROOT=/srv/challenge/xerte
LIVE_ROOT=/srv/runtime/xerte
NEXT_ROOT=/srv/runtime/xerte.next
PREVIOUS_ROOT=/srv/runtime/xerte.previous
MANIFEST=/arena/php-manifest
PIDFILE=/run/xerte-apache.pid
LOG=/var/log/xerte-apache.log

stop_apache() {
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
    rm -f "$PIDFILE" /var/run/apache2/apache2.pid
}

# A restart is a deployment boundary. Retire the serving generation before
# inspecting defender edits so a rejected candidate cannot leave stale code
# serving, and direct edits under SOURCE_ROOT never affect the live generation.
stop_apache
if [ -e "$PREVIOUS_ROOT" ] || [ -L "$PREVIOUS_ROOT" ]; then
    # A prior rejected attempt already retired the last serving generation.
    # Discard only its never-served candidate, if one was partially staged.
    rm -rf "$LIVE_ROOT"
elif [ -e "$LIVE_ROOT" ] || [ -L "$LIVE_ROOT" ]; then
    mv "$LIVE_ROOT" "$PREVIOUS_ROOT"
fi

if [ "$MODE" != initial ]; then
    # Only files shipped by the pinned revision are checked, so uploaded
    # project content can never decide whether a defence may restart.
    list=$(mktemp)
    trap 'rm -f "$list"' EXIT
    (cd "$SOURCE_ROOT" && while IFS= read -r rel; do
        [ -f "$rel" ] && printf '%s\n' "$rel"
    done < "$MANIFEST") > "$list"
    # php -l checks one file per process, so fan out rather than batch.
    errors=$(cd "$SOURCE_ROOT" && xargs -a "$list" -d '\n' -r -n 1 -P 4 \
        php -d error_reporting=E_ERROR -l 2>&1 \
        | grep -v -e '^No syntax errors detected' -e '^xargs: ' || true)
    rm -f "$list"
    trap - EXIT
    if [ -n "$errors" ]; then
        echo "PHP syntax check failed:" >&2
        printf '%s\n' "$errors" | head -40 >&2
        exit 1
    fi
fi

# Stage a complete serving generation. USER-FILES, import, and error_logs are
# symlinks into application data, so project state survives generation swaps.
rm -rf "$NEXT_ROOT"
cp -a "$SOURCE_ROOT" "$NEXT_ROOT"
mv "$NEXT_ROOT" "$LIVE_ROOT"

if ! apachectl configtest >/tmp/configtest 2>&1; then
    echo "Apache configuration check failed:" >&2
    head -20 /tmp/configtest >&2
    rm -rf "$LIVE_ROOT"
    exit 1
fi

# The serving generation is application-writable because the retained Xerte
# deployment requires Apache to write the web root, but it is not defender-
# source writable: arena_agent owns only SOURCE_ROOT and is not in www-data.
chown -R root:www-data "$LIVE_ROOT"
chmod -R u=rwX,g=rwX,o=rX "$LIVE_ROOT"

# Carry application-owned mutable state from the retired generation into the
# validated candidate as real directories. Xerte deliberately rejects symlinked
# upload roots because its path guard requires realpath(path) == path.
if [ -d "$PREVIOUS_ROOT" ]; then
    for name in USER-FILES import error_logs; do
        if [ -d "$PREVIOUS_ROOT/$name" ]; then
            rm -rf "$LIVE_ROOT/$name"
            cp -a "$PREVIOUS_ROOT/$name" "$LIVE_ROOT/$name"
        fi
    done
fi

setsid apache2-foreground >>"$LOG" 2>&1 &
echo $! > "$PIDFILE"

for _ in $(seq 1 200); do
    if curl -fsS -o /dev/null --max-time 2 http://127.0.0.1/index.php; then
        rm -rf "$PREVIOUS_ROOT"
        echo "Xerte ready (mode=$MODE)"
        exit 0
    fi
    sleep .25
done
echo "Xerte failed to become ready" >&2
tail -20 "$LOG" >&2 2>/dev/null || true
stop_apache
rm -rf "$LIVE_ROOT"
exit 1
