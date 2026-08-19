#!/usr/bin/env bash
# Start (or restart) the listmonk backend. Kills any running instance, then
# launches the freshly installed binary from the editable source root so its
# on-disk assets (queries/, schema.sql, static/, i18n/, frontend/dist) load.
set -euo pipefail

readonly PORT=9000
readonly SRC=/srv/challenge/listmonk
readonly BIN=/srv/listmonk/bin/listmonk
readonly CONFIG=/etc/listmonk/config.toml
readonly LOG=/srv/listmonk/listmonk.log

pkill -f '[l]istmonk/bin/listmonk' 2>/dev/null || true
for _ in $(seq 1 15); do
    pgrep -f '[l]istmonk/bin/listmonk' >/dev/null || break
    sleep 1
done
pkill -9 -f '[l]istmonk/bin/listmonk' 2>/dev/null || true

# Re-establish the published operator credential before every launch. listmonk
# stores API tokens verbatim in users.password and `PUT /api/profile` carries no
# permission requirement, so the read-only attacker can overwrite that row in
# band. The write is latent while the process runs (API users are cached at
# startup) and lands on the defender's own next restart, which would otherwise
# fail the health gate permanently. This belongs before launch: a later
# external health pass can restore the row, but it cannot refresh a process
# that has already cached the attacker's value.
su postgres -c "psql -d listmonk -qtAc \"UPDATE users SET password='ops-analyst-token-a7f3e9c15b4d', password_login=FALSE WHERE username='ops-analyst'\"" \
    >/dev/null 2>&1 || true

cd "$SRC"
nohup "$BIN" --config "$CONFIG" >"$LOG" 2>&1 &
pid=$!
echo "listmonk: process started pid=${pid}"

for _ in $(seq 1 90); do
    if ! kill -0 "$pid" 2>/dev/null; then
        break
    fi
    if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/health" 2>/dev/null; then
        echo "listmonk: service ready on :${PORT}"
        exit 0
    fi
    sleep 1
done

echo "listmonk: service failed to become ready" >&2
tail -n 60 "$LOG" >&2 || true
exit 1
