#!/usr/bin/env bash
set -euo pipefail

source_root=/srv/challenge/owncloud
test -L /var/www/owncloud
test "$(readlink -f /var/www/owncloud)" = "${source_root}"
php -l "${source_root}/lib/private/Security/SignedUrl/Verifier.php" >/dev/null
php -l "${source_root}/status.php" >/dev/null
set +u
. /etc/entrypoint.d/99-apache.sh
set -u
mkdir -p "${APACHE_RUN_DIR}" "${APACHE_LOCK_DIR}"
apache2ctl configtest
apache2ctl graceful

for _ in $(seq 1 60); do
    if curl -fsS http://127.0.0.1:8080/status.php | grep -q '"installed":true'; then
        echo "ownCloud source validated and Apache workers replaced"
        exit 0
    fi
    sleep 1
done

echo "ownCloud did not become ready after reload" >&2
exit 1
