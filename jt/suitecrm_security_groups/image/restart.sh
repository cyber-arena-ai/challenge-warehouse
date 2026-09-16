#!/bin/sh
set -eu

SOURCE=/srv/challenge/suitecrm
RUNTIME=/srv/runtime
GENERATIONS=$RUNTIME/generations
LINT=/tmp/suitecrm-lint.log
candidate=
started=$(date +%s)

stop_service() {
    for service in /run/service/php-fpm /run/service/nginx; do
        /command/s6-svc -d "$service" >/dev/null 2>&1
    done
    if /command/s6-svwait -d -t 5000 \
        /run/service/php-fpm /run/service/nginx >/dev/null 2>&1 \
        && ! live_service_processes; then
        return 0
    fi
    for service in /run/service/php-fpm /run/service/nginx; do
        /command/s6-svc -k -d "$service" >/dev/null 2>&1 || true
    done
    pkill -KILL -x php-fpm >/dev/null 2>&1 || true
    pkill -KILL -x nginx >/dev/null 2>&1 || true
    if ! /command/s6-svwait -d -t 2000 \
        /run/service/php-fpm /run/service/nginx >/dev/null 2>&1 \
        || live_service_processes; then
        echo "SuiteCRM serving processes did not stop" >&2
        return 1
    fi
}

live_service_processes() {
    for name in php-fpm nginx; do
        for pid in $(pgrep -x "$name" 2>/dev/null || true); do
            process_alive "$pid" && return 0
        done
    done
    return 1
}

process_alive() {
    [ -r "/proc/$1/stat" ] || return 1
    stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    case "$stat" in
        *') '*) ;;
        *) return 1 ;;
    esac
    state=${stat##*) }
    state=${state%% *}
    [ "$state" != Z ]
}

fail_closed() {
    status=$?
    trap - EXIT INT TERM
    stop_service || true
    rm -f /run/suitecrm/arena.ready
    [ ! -L "$RUNTIME/current" ] || unlink "$RUNTIME/current"
    if [ -n "$candidate" ] && [ -d "$candidate" ]; then
        rm -rf "$candidate"
    fi
    exit "$status"
}
trap fail_closed EXIT
trap 'exit 1' INT TERM

stop_service
rm -f /run/suitecrm/arena.ready
[ ! -L "$RUNTIME/current" ] || unlink "$RUNTIME/current"

previous=$(readlink -f "$RUNTIME/last-good" 2>/dev/null || true)
case "$previous" in
    "$GENERATIONS"/*) [ -d "$previous" ] ;;
    *) echo "last good SuiteCRM generation unavailable" >&2; exit 1 ;;
esac
if find "$SOURCE" -type l -print -quit | grep -q .; then
    echo "editable SuiteCRM tree contains unsupported symbolic links" >&2
    exit 1
fi
if find "$previous/upload" -type l -print -quit 2>/dev/null | grep -q .; then
    echo "persisted SuiteCRM upload state contains symbolic links" >&2
    exit 1
fi

candidate=$(mktemp -d "$GENERATIONS/candidate.XXXXXX")
cp -R "$SOURCE/." "$candidate/"
mkdir -p "$candidate/Api/V8/OAuth2" "$candidate/upload"
for key in private.key public.key; do
    [ -f "$previous/Api/V8/OAuth2/$key" ] \
        || { echo "OAuth key state unavailable" >&2; exit 1; }
    cp -p "$previous/Api/V8/OAuth2/$key" "$candidate/Api/V8/OAuth2/$key"
done
if [ -d "$previous/upload" ]; then
    cp -a "$previous/upload/." "$candidate/upload/"
fi

find "$candidate" \
    -path "$candidate/vendor" -prune -o \
    -path "$candidate/cache" -prune -o \
    -path "$candidate/upload" -prune -o \
    -path "$candidate/include/SugarObjects/templates/basic/Dashlets/Dashlet/m-n-Dashlet.php" -prune -o \
    -path "$candidate/include/SugarObjects/templates/file/views/view.edit.php" -prune -o \
    -type f -name '*.php' -print0 \
    | xargs -0 -n1 -P4 php -l >"$LINT" 2>&1 || {
        tail -40 "$LINT" >&2
        exit 1
    }

/arena/normalize-generation.sh "$candidate"
next_link="$RUNTIME/.current.$$"
ln -s "$candidate" "$next_link"
mv -Tf "$next_link" "$RUNTIME/current"

for service in /run/service/php-fpm /run/service/nginx; do
    /command/s6-svc -u "$service"
done
for _ in $(seq 1 600); do
    status=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
        'http://127.0.0.1:8080/index.php?action=Login&module=Users' 2>/dev/null || true)
    if [ "$status" = 200 ]; then
        /arena/finalize-generation.sh "$RUNTIME" "$candidate" "$previous"
        : > /run/suitecrm/arena.ready
        candidate=
        trap - EXIT INT TERM
        printf 'READY seconds=%s\n' "$(($(date +%s) - started))"
        exit 0
    fi
    sleep .1
done
echo "SuiteCRM failed to become ready" >&2
exit 1
