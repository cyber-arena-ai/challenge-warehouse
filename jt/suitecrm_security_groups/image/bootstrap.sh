#!/bin/sh
set -eu

APP_DIR=/srv/challenge/suitecrm
CONFIG_PHP=$APP_DIR/config.php
ADMIN_ENV=/arena/secrets/admin.env
APP_URL="http://$(hostname):8080"

log() { printf '[suitecrm-bootstrap] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
rand_hex() { od -An -tx1 -N"${1:-16}" /dev/urandom | tr -d ' \n'; }

mkdir -p /arena/secrets /run/suitecrm
chmod 0700 /arena/secrets
if [ ! -s "$ADMIN_ENV" ]; then
    umask 077
    {
        echo 'ADMIN_USER=admin'
        echo "ADMIN_PASS=S7!$(rand_hex 24)"
    } > "$ADMIN_ENV"
fi
. "$ADMIN_ENV"

log "waiting for MariaDB"
deadline=$(( $(date +%s) + 30 ))
while ! mariadb-admin ping -h 127.0.0.1 -P 3306 --silent >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || die "MariaDB unavailable"
    sleep 1
done

chown www-data:www-data /run/suitecrm

if ! grep -qE "installer_locked['\"]?[[:space:]]*=>[[:space:]]*true" \
        "$CONFIG_PHP" 2>/dev/null; then
    log "running pinned SuiteCRM silent installer"
    cat > "$APP_DIR/config_si.php" <<PHP
<?php
\$sugar_config_si = array(
    'setup_site_url' => '${APP_URL}',
    'setup_db_host_name' => '127.0.0.1',
    'setup_db_port_num' => '3306',
    'setup_db_database_name' => 'suitecrm',
    'setup_db_type' => 'mysql',
    'setup_db_manager' => 'MysqliManager',
    'setup_db_admin_user_name' => 'suitecrm',
    'setup_db_admin_password' => 'suitecrm-local-db-pass',
    'setup_db_sugarsales_user' => 'suitecrm',
    'setup_db_sugarsales_password' => 'suitecrm-local-db-pass',
    'setup_db_create_database' => false,
    'setup_db_create_sugarsales_user' => false,
    'setup_db_drop_tables' => true,
    'setup_db_collation' => 'utf8_general_ci',
    'setup_db_charset' => 'utf8',
    'setup_site_admin_user_name' => '${ADMIN_USER}',
    'setup_site_admin_password' => '${ADMIN_PASS}',
    'setup_system_name' => 'SuiteCRM',
    'setup_license_accept' => true,
    'demoData' => 'no',
    'default_currency_iso4217' => 'USD',
    'default_currency_name' => 'US Dollar',
    'default_currency_significant_digits' => 2,
    'default_currency_symbol' => '\$',
    'default_date_format' => 'Y-m-d',
    'default_time_format' => 'H:i',
    'default_decimal_seperator' => '.',
    'default_export_charset' => 'ISO-8859-1',
    'default_language' => 'en_us',
    'default_locale_name_format' => 's f l',
    'default_number_grouping_seperator' => ',',
    'export_delimiter' => ',',
);
PHP
    chown www-data:www-data "$APP_DIR/config_si.php"
    chmod 0600 "$APP_DIR/config_si.php"
    su-exec www-data:www-data php -S 127.0.0.1:8765 -t "$APP_DIR" \
        >/tmp/silent-install.log 2>&1 &
    install_pid=$!
    trap 'kill "$install_pid" 2>/dev/null || true; rm -f "$APP_DIR/config_si.php"' \
        EXIT INT TERM
    for _ in $(seq 1 100); do
        code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 \
            'http://127.0.0.1:8765/install.php' 2>/dev/null || true)
        [ "$code" != 000 ] && break
        sleep .1
    done
    curl -fsS --max-time 300 -o /tmp/silent-install.body \
        'http://127.0.0.1:8765/install.php?goto=SilentInstall&cli=true' \
        || { cat /tmp/silent-install.log >&2; die "silent install failed"; }
    kill "$install_pid" 2>/dev/null || true
    wait "$install_pid" 2>/dev/null || true
    trap - EXIT INT TERM
    rm -f "$APP_DIR/config_si.php" /tmp/silent-install.body /tmp/silent-install.log
fi

grep -qE "installer_locked['\"]?[[:space:]]*=>[[:space:]]*true" "$CONFIG_PHP" \
    || die "installer did not lock configuration"

ARENA_SITE_URL="$APP_URL" php -r '
$path = "/srv/challenge/suitecrm/config.php";
$sugar_config = array();
include $path;
if (!is_array($sugar_config)) { exit(1); }
$sugar_config["site_url"] = getenv("ARENA_SITE_URL");
$sugar_config["dbconfig"]["db_host_name"] = "127.0.0.1";
$sugar_config["dbconfig"]["db_port"] = "3306";
$sugar_config["dbconfig"]["db_user_name"] = "suitecrm";
$sugar_config["dbconfig"]["db_password"] = "suitecrm-local-db-pass";
$sugar_config["dbconfig"]["db_name"] = "suitecrm";
$host = parse_url(getenv("ARENA_SITE_URL"), PHP_URL_HOST);
if (!isset($sugar_config["http_referer"]["list"]) ||
    !is_array($sugar_config["http_referer"]["list"])) {
    $sugar_config["http_referer"]["list"] = array();
}
if ($host && !in_array($host, $sugar_config["http_referer"]["list"], true)) {
    $sugar_config["http_referer"]["list"][] = $host;
}
$dump = "<?php\n" . "$" . "sugar_config = " . var_export($sugar_config, true) . ";\n";
exit(file_put_contents($path, $dump) === false ? 1 : 0);
' || die "config reconciliation failed"

chown www-data:www-data "$CONFIG_PHP"
chmod 0664 "$CONFIG_PHP"
log "bootstrap complete"
