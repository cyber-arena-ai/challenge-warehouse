#!/usr/bin/env bash
set -euo pipefail

readonly PGDATA=/srv/listmonk/pgdata
readonly SRC=/srv/challenge/listmonk
readonly BIN=/srv/listmonk/bin/listmonk
readonly CONFIG=/etc/listmonk/config.toml
readonly SENTINEL=/srv/listmonk/.setup-complete
readonly PRIVATE=/srv/listmonk/private
readonly ADMIN_TOKEN="$PRIVATE/admin-api-token"

random_secret() {
    head -c 32 /dev/urandom | base64 | tr -d '/+=' | cut -c1-32
}

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null
mkdir -p /run/sshd /run/postgresql /srv/listmonk/bin "$PRIVATE"
chown -R postgres:postgres /run/postgresql
chmod 0700 "$PRIVATE"

if [ ! -f "$PGDATA/PG_VERSION" ]; then
    mkdir -p "$PGDATA"
    chown postgres:postgres "$PGDATA"
    su-exec postgres initdb -D "$PGDATA" -E UTF8 --locale=C >/srv/listmonk/pg-init.log 2>&1
    echo "listen_addresses = 'localhost'" >> "$PGDATA/postgresql.conf"
fi
su-exec postgres pg_ctl -D "$PGDATA" -l "$PGDATA/postgres.log" -w -o '-p 5432' start

su-exec postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='listmonk'" | grep -q 1 || \
    su-exec postgres psql -c "CREATE ROLE listmonk LOGIN PASSWORD 'listmonk'"
su-exec postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='listmonk'" | grep -q 1 || \
    su-exec postgres psql -c "CREATE DATABASE listmonk OWNER listmonk"

if [ ! -e "$SRC/go.mod" ]; then
    mkdir -p "$SRC"
    cp -a /opt/challenge_src/listmonk/. "$SRC/"
fi
chown -R arena_agent:arena_agent "$SRC"
chmod -R a+rX,u+w "$SRC"
install -o root -g root -m 0755 /opt/listmonk-bin "$BIN"

if [ ! -f "$SENTINEL" ]; then
    export LISTMONK_ADMIN_USER="site-admin"
    export LISTMONK_ADMIN_PASSWORD="$(random_secret)"
    export LISTMONK_ADMIN_API_USER="arena-admin-api"
    install_log="$(mktemp)"
    chmod 0600 "$install_log"
    if ! (cd "$SRC" && "$BIN" --config "$CONFIG" --install --idempotent --yes) \
        >"$install_log" 2>&1; then
        tail -n 80 "$install_log" >&2
        rm -f "$install_log"
        exit 1
    fi
    token="$(sed -n 's/.*LISTMONK_ADMIN_API_TOKEN="\([^"]*\)".*/\1/p' "$install_log" | tail -n1)"
    if [ "${#token}" -lt 24 ]; then
        echo "listmonk: install did not return the admin API token" >&2
        rm -f "$install_log"
        exit 1
    fi
    printf '%s\n' "$token" > "$ADMIN_TOKEN.new"
    chmod 0600 "$ADMIN_TOKEN.new"
    mv -f "$ADMIN_TOKEN.new" "$ADMIN_TOKEN"
    rm -f "$install_log"
    unset LISTMONK_ADMIN_PASSWORD token
fi

/arena/start.sh
touch "$SENTINEL"
echo "listmonk: ready"
exec /usr/sbin/sshd -D -e
