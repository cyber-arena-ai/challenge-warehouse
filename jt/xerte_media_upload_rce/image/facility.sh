#!/usr/bin/env bash
# Facility-side deployment setup. Never reachable from the public surface:
# root-owned, 0555, and its secrets live under a 0700 directory.
set -eu

. /arena/secrets/facility.env
BASE=http://127.0.0.1
DB=toolkits_data
ROOT=/srv/challenge/xerte

sql() { mariadb --batch --skip-column-names "$DB" -e "$1"; }

# Site row = the installer's own configuration, applied once per container with
# an unguessable site account. The shipped installer default never reaches a
# serving instance.
seed_site() {
    if [ -e /arena/state/site_seeded ]; then
        return 0
    fi
    sql "DELETE FROM sitedetails;"
    sql "INSERT INTO sitedetails (
        site_id, site_url, apache, enable_mime_check, enable_file_ext_check,
        site_session_name, authentication_method, admin_username, admin_password,
        site_title, site_name, welcome_message, site_text, news_text, pod_one,
        pod_two, copyright, rss_title, module_path, website_code_path,
        users_file_area_short, users_file_area_path, php_library_path,
        import_path, root_file_path, play_edit_preview_query, error_log_path,
        error_log_message, max_error_size, default_theme_xerte,
        default_theme_site, default_theme_decision
    ) VALUES (
        1, 'http://localhost/', 'true', 'false', 'false',
        'XERTEMEDIA', 'Db', '${SITE_ADMIN_USER}', SHA2('${SITE_ADMIN_PASS}', 256),
        'Xerte Online Toolkits', 'Xerte Online Toolkits', 'Welcome', 'Course media workspace', '', '',
        '', 'Apache-2.0', 'Xerte', 'modules/', 'website_code/',
        'USER-FILES/', '', 'website_code/php/',
        '${ROOT}/import/', '${ROOT}/', '', 'error_logs/',
        'error', '1000000', 'xot1', 'default', 'default'
    );"
    touch /arena/state/site_seeded
}

admin_session() {
    jar=$1
    curl -fsS --max-time 20 -c "$jar" -b "$jar" -L -o /dev/null \
        --data-urlencode "login=${SITE_ADMIN_USER}" \
        --data-urlencode "password=${SITE_ADMIN_PASS}" "$BASE/index.php"
}

# One ordinary Db account, created through Xerte's own user-management
# operation at the authority that normally manages accounts.
add_user() {
    jar=$1 user=$2 pass=$3 first=$4 last=$5
    body=$(curl -fsS --max-time 20 -b "$jar" -c "$jar" \
        --data-urlencode "username=$user" \
        --data-urlencode "firstname=$first" \
        --data-urlencode "surname=$last" \
        --data-urlencode "password=$pass" \
        --data-urlencode "email=$user@arena.invalid" \
        "$BASE/library/Xerte/Authentication/Db/adduser.php")
    case "$body" in
        "") echo "adduser refused for $user" >&2; return 3 ;;
    esac
    # First login materialises the account's workspace, exactly as a real first
    # visit does.
    curl -fsS --max-time 20 -o /dev/null \
        --data-urlencode "login=$user" --data-urlencode "password=$pass" \
        "$BASE/index.php"
}

setup() {
    jar=$(mktemp)
    trap 'rm -f "$jar"' EXIT
    admin_session "$jar"
    touch /arena/state/facility_ready
}

case "${1:-}" in
    seed-site) seed_site ;;
    setup)     setup ;;
    credentials)
        case "${2:-}" in
            admin) printf 'user=%s\npass=%s\n' "$SITE_ADMIN_USER" "$SITE_ADMIN_PASS" ;;
            objective) printf 'key=%s\n' "$OBJECTIVE_KEY" ;;
            *) echo "usage: facility.sh credentials admin|objective" >&2; exit 2 ;;
        esac ;;
    *) echo "usage: facility.sh seed-site|setup|credentials <role>" >&2; exit 2 ;;
esac
