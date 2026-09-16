#!/usr/bin/env bash
set -euo pipefail

EDITABLE=/srv/challenge/horizont
DATA=/var/lib/horizont/data
RUNTIME=/srv/runtime/horizont
GENERATIONS=$RUNTIME/generations
CURRENT=$RUNTIME/current
PIDFILE=/run/horizont.pid
LOG=/var/log/horizont.log
GENERATION=''
ready=0

stop_service() {
    if [ -s "$PIDFILE" ]; then
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        case "$pid" in
            ''|*[!0-9]*) ;;
            *) kill -TERM "$pid" 2>/dev/null || true ;;
        esac
    fi
    pkill -TERM -u www-data -f '[/]usr/local/bin/php -S 0.0.0.0:8080 /arena/router.php' \
        2>/dev/null || true
    for _ in $(seq 1 50); do
        if ! pgrep -u www-data -f '[/]usr/local/bin/php -S 0.0.0.0:8080 /arena/router.php' \
                >/dev/null 2>&1; then
            rm -f "$PIDFILE"
            return 0
        fi
        sleep 0.1
    done
    pkill -KILL -u www-data -f '[/]usr/local/bin/php -S 0.0.0.0:8080 /arena/router.php' \
        2>/dev/null || true
    rm -f "$PIDFILE"
    ! pgrep -u www-data -f '[/]usr/local/bin/php -S 0.0.0.0:8080 /arena/router.php' \
        >/dev/null 2>&1
}

cleanup() {
    rc=$?
    if [ "$ready" -ne 1 ]; then
        stop_service || true
        if [ -n "$GENERATION" ] && [ -d "$GENERATION" ]; then
            rm -rf -- "$GENERATION"
        fi
    fi
    exit "$rc"
}
trap cleanup EXIT

test -f "$EDITABLE/artisan"
test -f "$EDITABLE/app/Controllers/FileManagerController.php"
mkdir -p "$GENERATIONS"
GENERATION="$(mktemp -d "$GENERATIONS/candidate.XXXXXXXX")"
cp -a "$EDITABLE/." "$GENERATION/"
rm -rf "$GENERATION/storage"
rm -f "$GENERATION/.env"
ln -s "$DATA/storage" "$GENERATION/storage"
ln -s "$DATA/.env" "$GENERATION/.env"
chown -hR root:www-data "$GENERATION"
chmod -R u+rwX,go=rX "$GENERATION"

find "$GENERATION/app" "$GENERATION/bootstrap" "$GENERATION/config" \
     "$GENERATION/database" "$GENERATION/resources" "$GENERATION/routes" \
     -type f -name '*.php' ! -name '*.blade.php' -print0 \
    | xargs -0 -n1 php -l >/tmp/horizont-lint.log
find "$GENERATION" -maxdepth 1 -type f -name '*.php' -print0 \
    | xargs -0 -n1 php -l >>/tmp/horizont-lint.log
cd "$GENERATION"
runuser -u www-data -- php artisan --version >/tmp/horizont-artisan.log

stop_service
link="$RUNTIME/current.$$"
ln -s "$GENERATION" "$link"
mv -Tf "$link" "$CURRENT"

touch "$LOG"
chown www-data:www-data "$LOG"
start-stop-daemon --start --background --make-pidfile --pidfile "$PIDFILE" \
    --chuid www-data:www-data --chdir "$CURRENT" --startas /usr/bin/env -- \
    PHP_CLI_SERVER_WORKERS=4 /usr/local/bin/php -S 0.0.0.0:8080 /arena/router.php \
    >>"$LOG" 2>&1

for _ in $(seq 1 45); do
    if php -r '$b=@file_get_contents("http://127.0.0.1:8080/admin/login"); exit($b!==false && strpos($b,"csrf-token")!==false ? 0 : 1);'; then
        find "$GENERATIONS" -mindepth 1 -maxdepth 1 -type d \
            ! -name "$(basename "$GENERATION")" -exec rm -rf -- {} +
        ready=1
        trap - EXIT
        echo "horizont-cms-filemanager: source validated and service replaced"
        exit 0
    fi
    sleep 1
done

tail -n 80 "$LOG"
exit 1
