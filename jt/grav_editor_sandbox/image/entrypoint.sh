#!/usr/bin/env bash
# First-boot setup for the Grav editor-sandbox vulbox, then hand off to sshd.
#   - ssh host keys
#   - a per-box, root-only facility-admin credential (never leaves this file;
#     the facility reads it through privileged docker-exec, nothing else can)
#   - cold-start Grav provisioning through the supported API (idempotent)
#   - the service itself, spawned through the same restart.sh the defender uses
set -e

SECRETS=/arena/secrets/facility.env
STATE=/arena/state/setup.done
API_CONFIG=/srv/challenge/grav/user/config/plugins/api.yaml

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

# --- Facility-admin credential: generated once, per box, root-only. -----------
# A fixed or image-baked credential would be readable by every attacker (each is
# root on its OWN box and would then hold the opponent's admin login), so both
# halves are random per container and never appear in a prompt, handle, log line
# or registry row.
_rand_hex() { od -An -tx1 -N"${1:-16}" /dev/urandom | tr -d ' \n'; }
if [ ! -s "$SECRETS" ]; then
    umask 077
    {
        echo "FACILITY_USER=steward$(_rand_hex 6)"
        echo "FACILITY_PASS=Fa1-$(_rand_hex 18)"
    } > "$SECRETS"
    chown root:root "$SECRETS"
    chmod 600 "$SECRETS"
fi

# The API plugin auto-generates this setting on first token issuance, but the
# built-in PHP server keeps the pre-write configuration for later requests.
# Seed the ordinary application setting before startup so the setup token is
# immediately reusable. The scored credential replaces it later through the
# authenticated Grav API.
if [ ! -f "$STATE" ]; then
    install -d -o arena_agent -g grav -m 0770 "$(dirname "$API_CONFIG")"
    (umask 007; printf 'auth:\n  jwt_secret: %s\n' "$(_rand_hex 32)" > "$API_CONFIG")
    chown arena_agent:grav "$API_CONFIG"
    chmod 660 "$API_CONFIG"
fi

# --- Spawn the service (cold start goes through the rebuild path). -----------
/arena/restart.sh initial || echo "entrypoint: initial start failed (see /var/log/grav-svc.log)" >&2

# --- Cold-start Grav provisioning: first admin + the checker's editor. --------
if [ ! -f "$STATE" ]; then
    if php /arena/setup.php; then
        touch "$STATE"
    else
        echo "entrypoint: Grav provisioning failed" >&2
    fi
fi

exec /usr/sbin/sshd -D -e
