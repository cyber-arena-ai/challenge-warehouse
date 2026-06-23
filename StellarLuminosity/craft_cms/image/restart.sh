#!/usr/bin/env bash
# Framework restart script for craft-cms.
#
# Invoked by the MCP `restart_service` tool via docker exec (root). Lints the
# defender's edited front controller, copies it into the live webroot, clears
# Craft's compiled caches, and gracefully reloads Apache.
#
# PHP is interpreted — "compile" here is `php -l`. A syntax error aborts the
# script (set -e) so the bad file is never deployed and the failure surfaces
# in the restart CheckResult. Mode 555, root-owned: agent can read+exec only.

set -e

SRC="/srv/challenge/craft_cms/index.php"
DST="/var/www/html/web/index.php"

echo "[*] Linting ${SRC}..."
php -l "$SRC"

echo "[*] Deploying front controller..."
cp -f "$SRC" "$DST"
chown www-data:www-data "$DST"

echo "[*] Clearing Craft caches (best-effort)..."
su -s /bin/sh www-data -c 'cd /var/www/html && php craft clear-caches/all' \
    >/dev/null 2>&1 || true

echo "[*] Reloading Apache..."
apache2ctl graceful

# Brief settle, then confirm Craft still answers on the live port.
sleep 1
curl -sf -o /dev/null --max-time 8 "http://127.0.0.1/index.php?p=admin/login"

echo "craft-cms redeployed; index.php=$(wc -c < "$DST") bytes"
