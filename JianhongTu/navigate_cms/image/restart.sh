#!/bin/sh
set -eu

SOURCE=/srv/challenge/navigate
RUNTIME=/srv/runtime/navigate
GENERATIONS=${RUNTIME}/generations
CURRENT=${RUNTIME}/current
staging=
generation=
previous=
completed=false
cleanup_armed=false
lock_open=false
LOCK=${RUNTIME}/restart.lock

is_generation_path() {
    candidate=$1
    case "${candidate}" in
        "${GENERATIONS}"/*)
            leaf=${candidate#"${GENERATIONS}"/}
            [ -n "${leaf}" ] && [ "${leaf#*/}" = "${leaf}" ]
            ;;
        *) return 1 ;;
    esac
}

apache_is_live() {
    ps -eo stat=,comm= \
        | awk '$2 == "apache2" && $1 !~ /^Z/ { found=1 } END { exit found ? 0 : 1 }'
}

stop_apache() {
    apache2ctl -k stop >/tmp/navigate-apache-stop.log 2>&1 || true
    for _attempt in $(seq 1 30); do
        apache_is_live || break
        sleep 0.2
    done
    if apache_is_live; then
        pkill -TERM -x apache2 2>/dev/null || true
        sleep 1
    fi
    if apache_is_live; then
        pkill -KILL -x apache2 2>/dev/null || true
    fi
    rm -f /var/run/apache2/apache2.pid
    ! apache_is_live
}

release_lock() {
    if [ "${lock_open}" = true ]; then
        flock -u 9 2>/dev/null || true
        exec 9>&-
        lock_open=false
    fi
}

finish() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "${cleanup_armed}" = true ] && [ "${completed}" != true ]; then
        status=1
    fi
    if [ "${status}" -ne 0 ] \
        && [ "${cleanup_armed}" = true ] \
        && [ "${completed}" != true ]; then
        stop_apache || true
        rm -f "${CURRENT}.new"
        if [ -n "${generation}" ] && is_generation_path "${generation}"; then
            active=$(readlink "${CURRENT}" 2>/dev/null || true)
            if [ "${active}" = "${generation}" ]; then
                rm -f "${CURRENT}.new"
                if [ -n "${previous}" ] \
                    && is_generation_path "${previous}" \
                    && [ -d "${previous}" ]; then
                    ln -s "${previous}" "${CURRENT}.new"
                    mv -Tf "${CURRENT}.new" "${CURRENT}"
                else
                    rm -f "${CURRENT}"
                fi
            fi
            active=$(readlink "${CURRENT}" 2>/dev/null || true)
            if [ "${active}" != "${generation}" ] && [ -d "${generation}" ]; then
                rm -rf -- "${generation}"
            fi
        fi
    fi
    if [ -n "${staging}" ]; then
        rm -rf -- "${staging}"
    fi
    release_lock
    exit "${status}"
}
trap finish EXIT HUP INT TERM

install -d -o root -g root -m 0755 "${RUNTIME}" "${GENERATIONS}"
umask 077
exec 9>"${LOCK}"
lock_open=true
chown root:root "${LOCK}"
chmod 0600 "${LOCK}"
if ! flock -w 10 9; then
    echo "Navigate restart is already in progress" >&2
    exit 1
fi
cleanup_armed=true
if [ "${1:-}" = "--stop" ]; then
    stop_apache
    completed=true
    exit 0
fi

generation=${GENERATIONS}/$(date +%s%N)-$$
staging=${GENERATIONS}/.staging-$$
rm -rf -- "${staging}"
mkdir "${staging}"

if [ -n "$(find "${SOURCE}" -type l -print -quit)" ]; then
    echo "Navigate editable source contains a symbolic link" >&2
    exit 1
fi
if ! find "${SOURCE}" -type f -name '*.php' ! -name 'globals.setup.php' -print0 \
    | xargs -0 -n1 php -l > /tmp/navigate-php-lint.log 2>&1; then
    tail -n 80 /tmp/navigate-php-lint.log >&2 || true
    exit 1
fi
test -s "${SOURCE}/login.php"
test -s "${SOURCE}/navigate.php"
test -f "${SOURCE}/navigate_info.php"
test ! -L "${SOURCE}/navigate_info.php"
cp -a "${SOURCE}/." "${staging}/"

# Stop the old generation before snapshotting mutable application state. A
# failed stage or start leaves no stale Apache process serving the old tree.
stop_apache
if [ -L "${CURRENT}" ] && [ -d "${CURRENT}" ]; then
    previous=$(readlink -f "${CURRENT}")
    if ! is_generation_path "${previous}"; then
        echo "Navigate runtime generation is outside the generation root" >&2
        exit 1
    fi
    for state_dir in private cache updates; do
        if [ -e "${previous}/${state_dir}" ]; then
            rm -rf -- "${staging:?}/${state_dir}"
            cp -a "${previous}/${state_dir}" "${staging}/${state_dir}"
        fi
    done
elif [ -e "${CURRENT}" ] || [ -L "${CURRENT}" ]; then
    echo "Navigate runtime generation is invalid" >&2
    exit 1
fi

if [ -n "$(find "${staging}" -type l -print -quit)" ]; then
    echo "Navigate staged generation contains a symbolic link" >&2
    exit 1
fi
chown -R root:root "${staging}"
find "${staging}" -type d -exec chmod 0755 {} +
find "${staging}" -type f -exec chmod 0644 {} +
for state_dir in private cache updates; do
    if [ -d "${staging}/${state_dir}" ]; then
        chown -R root:www-data "${staging}/${state_dir}"
        find "${staging}/${state_dir}" -type d -exec chmod 0770 {} +
        find "${staging}/${state_dir}" -type f -exec chmod 0660 {} +
    fi
done
# The historical Picnik path overwrites this existing application endpoint.
# Keep only that app-owned sink writable by Apache; the rest of live code is
# root-owned and changes solely through a promoted source generation.
test -f "${staging}/navigate_info.php"
test ! -L "${staging}/navigate_info.php"
chown root:www-data "${staging}/navigate_info.php"
chmod 0664 "${staging}/navigate_info.php"
mv "${staging}" "${generation}"
staging=
rm -f "${CURRENT}.new"
ln -s "${generation}" "${CURRENT}.new"
mv -Tf "${CURRENT}.new" "${CURRENT}"

if ! apache2ctl start 9>&- > /tmp/navigate-apache-start.log 2>&1; then
    tail -n 80 /tmp/navigate-apache-start.log >&2 || true
    exit 1
fi
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 2 http://127.0.0.1/navigate/login.php >/dev/null; then
        completed=true
        if ! find "${GENERATIONS}" -mindepth 1 -maxdepth 1 -type d \
            ! -path "${generation}" -exec rm -rf -- {} +; then
            echo "Navigate obsolete generation cleanup failed" >&2
        fi
        echo "PHP lint and hard Apache replacement passed"
        exit 0
    fi
    sleep 1
done
echo "Navigate login did not recover" >&2
tail -n 80 /var/log/apache2/error.log >&2 || true
exit 1
