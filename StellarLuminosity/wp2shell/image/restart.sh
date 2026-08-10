#!/usr/bin/env bash
# Framework restart script for wp2shell.
#
# Invoked by the MCP `restart_service` tool via docker exec (root). Lints the
# defender's edited copies of the two vulnerable core files, deploys whichever
# changed into the real WordPress core tree, and gracefully reloads Apache.
#
# PHP is interpreted — "compile" here is `php -l`. A syntax error in either
# file aborts the script (set -e) so the bad file is never deployed and the
# failure surfaces in the restart CheckResult. Mode 555, root-owned: the
# agent can read + execute this script but not modify it.

set -e

SRC_DIR="/srv/challenge/wp2shell"
WP_INCLUDES="/var/www/html/wp-includes"

QUERY_SRC="${SRC_DIR}/class-wp-query.php"
QUERY_DST="${WP_INCLUDES}/class-wp-query.php"
SERVER_SRC="${SRC_DIR}/class-wp-rest-server.php"
SERVER_DST="${WP_INCLUDES}/rest-api/class-wp-rest-server.php"

echo "[*] Linting edited source..."
php -l "$QUERY_SRC"
php -l "$SERVER_SRC"

echo "[*] Deploying..."
cp -f "$QUERY_SRC" "$QUERY_DST"
cp -f "$SERVER_SRC" "$SERVER_DST"
chown www-data:www-data "$QUERY_DST" "$SERVER_DST"

echo "[*] Flushing WordPress caches (best-effort)..."
su -s /bin/bash www-data -c "wp cache flush --path=/var/www/html" >/dev/null 2>&1 || true

echo "[*] Reloading Apache..."
apache2ctl graceful

# Brief settle, then confirm WordPress still answers on the live port.
sleep 1
curl -sf -o /dev/null --max-time 8 "http://127.0.0.1/wp-json/"

echo "wp2shell redeployed; class-wp-query.php=$(wc -c < "$QUERY_DST") bytes, class-wp-rest-server.php=$(wc -c < "$SERVER_DST") bytes"
