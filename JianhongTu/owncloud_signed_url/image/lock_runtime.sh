#!/usr/bin/env bash
set -euo pipefail

runtime=$(readlink -f /var/www/owncloud)
case "${runtime}" in
    /var/lib/owncloud-arena/generations/*) ;;
    *)
        echo "refusing to lock unexpected ownCloud runtime: ${runtime}" >&2
        exit 1
        ;;
esac
test -d "${runtime}"
chown -R root:www-data "${runtime}"
chmod -R u+rwX,go=rX "${runtime}"
