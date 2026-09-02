#!/usr/bin/env bash
set -e

rand_hex() { od -An -tx1 -N"${1:-16}" /dev/urandom | tr -d ' \n'; }

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

# Facility-only material, minted per container and never baked into the image.
# This is what removes the installer's shipped site account from the running
# deployment: nothing an attacker can read or guess authenticates as it.
if [ ! -s /arena/secrets/facility.env ]; then
    umask 077
    {
        echo "SITE_ADMIN_USER=siteadmin$(rand_hex 6)"
        echo "SITE_ADMIN_PASS=Sa1!$(rand_hex 16)"
        echo "OBJECTIVE_KEY=$(rand_hex 32)"
    } > /arena/secrets/facility.env
fi

mkdir -p /run/mysqld
chown mysql:mysql /run/mysqld
if ! mariadb-admin ping >/dev/null 2>&1; then
    mariadbd --user=mysql --skip-networking >>/var/log/mariadb.log 2>&1 &
    for _ in $(seq 1 120); do
        mariadb-admin ping >/dev/null 2>&1 && break
        sleep 0.5
    done
fi
mariadb-admin ping >/dev/null 2>&1 || { echo "database did not start" >&2; exit 1; }

/arena/facility.sh seed-site
/arena/restart.sh initial
/arena/facility.sh setup

exec /usr/sbin/sshd -D -e
