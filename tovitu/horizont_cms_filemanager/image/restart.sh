#!/usr/bin/env bash
set -euo pipefail

EDITABLE=/srv/challenge/horizont
PIDFILE=/run/horizont.pid
LOG=/var/log/horizont.log

test -f "$EDITABLE/artisan"
test -f "$EDITABLE/app/Controllers/FileManagerController.php"
find "$EDITABLE/app" "$EDITABLE/bootstrap" "$EDITABLE/config" \
     "$EDITABLE/database" "$EDITABLE/resources" "$EDITABLE/routes" \
     -type f -name '*.php' ! -name '*.blade.php' -print0 \
    | xargs -0 -n1 php -l >/tmp/horizont-lint.log
find "$EDITABLE" -maxdepth 1 -type f -name '*.php' -print0 \
    | xargs -0 -n1 php -l >>/tmp/horizont-lint.log
cd "$EDITABLE"
runuser -u www-data -- php artisan --version >/tmp/horizont-artisan.log

start-stop-daemon --stop --pidfile "$PIDFILE" \
    --retry TERM/5/KILL/1 --remove-pidfile >/dev/null 2>&1 || true
rm -f "$PIDFILE"
touch "$LOG"
chown www-data:www-data "$LOG"
start-stop-daemon --start --background --make-pidfile --pidfile "$PIDFILE" \
    --chuid www-data:www-data --chdir "$EDITABLE" --startas /usr/bin/env -- \
    PHP_CLI_SERVER_WORKERS=4 /usr/local/bin/php -S 0.0.0.0:8080 /arena/router.php \
    >>"$LOG" 2>&1

for _ in $(seq 1 45); do
    if php -r '$b=@file_get_contents("http://127.0.0.1:8080/admin/login"); exit($b!==false && strpos($b,"csrf-token")!==false ? 0 : 1);'; then
        echo "horizont-cms-filemanager: source validated and service replaced"
        exit 0
    fi
    sleep 1
done

tail -n 80 "$LOG"
exit 1
