#!/usr/bin/env bash
set -euo pipefail

SOURCE=/srv/challenge/owncloud
RUNTIME_ROOT=/var/lib/owncloud-arena/generations
CURRENT=/var/lib/owncloud-arena/current
LAST_GOOD=/var/lib/owncloud-arena/last-good
READY=/run/owncloud-arena/ready
candidate=""
completed=false

apache_live() {
    ps -C apache2 -o stat= 2>/dev/null | grep -Eq '^[[:space:]]*[^Z]'
}

stop_apache() {
    pkill -TERM -x apache2 >/dev/null 2>&1 || true
    for _ in $(seq 1 15); do
        apache_live || return 0
        sleep 1
    done
    pkill -KILL -x apache2 >/dev/null 2>&1 || true
    for _ in $(seq 1 5); do
        apache_live || return 0
        sleep 1
    done
    return 1
}

cleanup_candidate() {
    case "${candidate}" in
        "${RUNTIME_ROOT}"/candidate.????????)
            if [[ -d "${candidate}" && ! -L "${candidate}" ]]; then
                rm -rf -- "${candidate}"
            fi
            ;;
    esac
}

prune_obsolete_candidates() {
    local active generation failed=false
    active=$(readlink -f "${CURRENT}") || return 1
    for generation in "${RUNTIME_ROOT}"/candidate.????????; do
        case "${generation}" in
            "${RUNTIME_ROOT}"/candidate.????????)
                if [[ -d "${generation}" && ! -L "${generation}" \
                    && "${generation}" != "${active}" ]]; then
                    rm -rf -- "${generation}" || failed=true
                fi
                ;;
        esac
    done
    [[ "${failed}" == false ]]
}

restart_exit() {
    rc=$?
    trap - EXIT
    if [[ "${completed}" != true && "${rc}" -eq 0 ]]; then
        rc=1
    fi
    if (( rc != 0 )); then
        rm -f "${READY}"
        stop_apache || true
        cleanup_candidate
    fi
    exit "${rc}"
}

trap restart_exit EXIT
rm -f "${READY}"

test -d "${SOURCE}"
test -L "${CURRENT}"
test -L "${LAST_GOOD}"
install -d -o root -g root -m 0755 "${RUNTIME_ROOT}"
candidate=$(mktemp -d "${RUNTIME_ROOT}/candidate.XXXXXXXX")
cp -a "${SOURCE}/." "${candidate}/"
rm -rf "${candidate}/config" "${candidate}/custom"
ln -s /mnt/data/config "${candidate}/config"
ln -s /mnt/data/apps "${candidate}/custom"
chown -R root:www-data "${candidate}"
chmod -R u+rwX,go=rX "${candidate}"

while read -r expected relative; do
    file="${candidate}/${relative}"
    actual=$(sha256sum "${file}" | cut -d ' ' -f 1)
    if [[ "${actual}" != "${expected}" ]]; then
        php -l "${file}" >/dev/null
    fi
done < /arena/php-lint-excludes.sha256
find "${candidate}" -type f -name '*.php' \
    ! -path "${candidate}/apps/files_external/3rdparty/google/auth/src/Cache/TypedItem.php" \
    ! -path "${candidate}/lib/composer/symfony/polyfill-intl-idn/bootstrap80.php" \
    ! -path "${candidate}/lib/composer/symfony/polyfill-mbstring/bootstrap80.php" \
    ! -path "${candidate}/lib/composer/symfony/polyfill-intl-normalizer/bootstrap80.php" \
    ! -path "${candidate}/lib/composer/symfony/console/Attribute/AsCommand.php" \
    ! -path "${candidate}/lib/composer/symfony/polyfill-intl-grapheme/bootstrap80.php" \
    ! -path "${candidate}/lib/composer/symfony/polyfill-iconv/bootstrap80.php" \
    ! -path "${candidate}/lib/composer/symfony/service-contracts/Attribute/SubscribedService.php" \
    ! -path "${candidate}/lib/composer/symfony/event-dispatcher/Attribute/AsEventListener.php" \
    ! -path "${candidate}/lib/composer/doctrine/cache/lib/Doctrine/Common/Cache/Psr6/TypedCacheItem.php" \
    -print0 \
    | xargs -0 -r -n 1 -P 4 php -l >/dev/null
set +u
export OWNCLOUD_DOMAIN="${HOSTNAME}:8080"
export OWNCLOUD_TRUSTED_DOMAINS="${HOSTNAME},${HOSTNAME%_prod}_ingress,localhost,127.0.0.1"
for script in $(find /etc/entrypoint.d -iname "*.sh" | sort); do
    . "${script}"
done
set -u
mkdir -p "${APACHE_RUN_DIR}" "${APACHE_LOCK_DIR}"
apache2ctl configtest >/dev/null

stop_apache
rm -f "${APACHE_PID_FILE}"
next_link="/var/lib/owncloud-arena/.current.$$"
ln -s "${candidate}" "${next_link}"
mv -Tf "${next_link}" "${CURRENT}"
apache2ctl start >>/var/log/owncloud-restart.log 2>&1

for _ in $(seq 1 90); do
    if apache_live \
        && curl -fsS --max-time 3 http://127.0.0.1:8080/status.php \
            | grep -q '"installed":true'; then
        next_good="/var/lib/owncloud-arena/.last-good.$$"
        ln -s "${candidate}" "${next_good}"
        mv -Tf "${next_good}" "${LAST_GOOD}"
        touch "${READY}"
        completed=true
        trap - EXIT
        if ! prune_obsolete_candidates; then
            echo "warning: could not prune obsolete ownCloud generations" >&2
        fi
        echo "ownCloud candidate generation validated and serving"
        exit 0
    fi
    sleep 1
done

echo "ownCloud candidate generation did not become ready" >&2
exit 1
