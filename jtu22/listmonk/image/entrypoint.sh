#!/usr/bin/env bash
# Container startup for listmonk.
#
# Boots the co-resident PostgreSQL, materializes the defender's editable source
# copy, installs the listmonk schema + default data, seeds the challenge
# identities/lists/subscribers over SQL, launches the backend, and finally execs
# sshd as PID 1. All setup runs once (guarded by a sentinel).
#
# Shortcut-safety: the primordial super-admin's password is randomized per boot
# and discarded, so a defender who holds root on their own box cannot read a
# baked admin credential and replay it against an opponent (every box differs).
# The only known account is the deliberately-limited `ops-analyst`, which cannot
# read the protected settings/users tables through its authorized workflow.
set -euo pipefail

readonly PGDATA=/srv/listmonk/pgdata
readonly PGBIN="$(ls -d /usr/lib/postgresql/*/bin | head -n1)"
readonly SRC=/srv/challenge/listmonk
readonly BIN=/srv/listmonk/bin/listmonk
readonly CONFIG=/etc/listmonk/config.toml
readonly SENTINEL=/srv/listmonk/.setup-complete

# ── SSH host keys ─────────────────────────────────────────────────────────────
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null
mkdir -p /run/sshd

# ── PostgreSQL (init once, then start) ────────────────────────────────────────
mkdir -p /srv/listmonk /run/postgresql
chown -R postgres:postgres /srv/listmonk /run/postgresql
if [ ! -f "$PGDATA/PG_VERSION" ]; then
    su postgres -c "$PGBIN/initdb -D $PGDATA -E UTF8 --locale=C" >/var/log/pg-init.log 2>&1
    echo "listen_addresses = 'localhost'" >> "$PGDATA/postgresql.conf"
fi
su postgres -c "$PGBIN/pg_ctl -D $PGDATA -l /srv/listmonk/postgres.log -w -o '-p 5432' start"

su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='listmonk'\"" | grep -q 1 || \
    su postgres -c "psql -c \"CREATE ROLE listmonk LOGIN PASSWORD 'listmonk'\""
su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='listmonk'\"" | grep -q 1 || \
    su postgres -c "psql -c \"CREATE DATABASE listmonk OWNER listmonk\""

# ── Defender's editable source copy + installed binary ────────────────────────
mkdir -p "$SRC" /srv/listmonk/bin
if [ ! -e "$SRC/go.mod" ]; then
    cp -a /opt/challenge_src/listmonk/. "$SRC/"
fi
chown -R arena_agent:arena_agent "$SRC"
chmod -R a+rX,u+w "$SRC"
install -o root -g root -m 0755 /opt/listmonk-bin "$BIN"

# ── One-time install + challenge seed ─────────────────────────────────────────
if [ ! -f "$SENTINEL" ]; then
    # Random, discarded super-admin password (not reproducible across boxes).
    export LISTMONK_ADMIN_USER="site-admin"
    export LISTMONK_ADMIN_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-20)"
    ( cd "$SRC" && "$BIN" --config "$CONFIG" --install --idempotent --yes ) \
        >/var/log/listmonk-install.log 2>&1
    unset LISTMONK_ADMIN_PASSWORD

    # Feed the root-only seed file via stdin so the postgres user (which cannot
    # read the 0600 file) still runs it; the redirect is performed by root.
    su postgres -c "psql -d listmonk -v ON_ERROR_STOP=1" \
        < /arena/seed.sql >/var/log/listmonk-seed.log 2>&1

    # Mark install+seed done BEFORE the backend is launched: neither step is
    # idempotent (the seed's INSERTs are unguarded), so a first start that fails
    # for any other reason must not re-enter this block on the next boot and
    # brick the box on a duplicate key.
    touch "$SENTINEL"
fi

# ── Every boot: revoke the plan-invisible SQL executors + assert none remain ───
# Idempotent, and deliberately outside the sentinel guard so the invariant is
# re-established on every start and a PostgreSQL that introduced a new escape
# hatch fails loudly here instead of shipping a silent bypass.
su postgres -c "psql -d listmonk -v ON_ERROR_STOP=1" \
    < /arena/harden.sql >/var/log/listmonk-harden.log 2>&1

# ── Launch the backend (loads the seeded API user into its auth cache) ────────
/arena/start.sh

echo "listmonk: ready"
exec /usr/sbin/sshd -D -e
