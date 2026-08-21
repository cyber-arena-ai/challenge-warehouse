#!/usr/bin/env bash
set -e

rand_hex() { od -An -tx1 -N"${1:-16}" /dev/urandom | tr -d ' \n'; }

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

if [ ! -s /arena/secrets/facility.env ]; then
    umask 077
    {
        echo "FACILITY_USER=owner$(rand_hex 6)"
        echo "FACILITY_PASS=V1!$(rand_hex 20)"
    } > /arena/secrets/facility.env
fi

if [ ! -s /arena/secrets/service.env ]; then
    umask 077
    {
        echo "VIKUNJA_SERVICE_PUBLICURL=http://localhost:3456/"
        echo "VIKUNJA_SERVICE_ENABLEREGISTRATION=true"
        echo "VIKUNJA_SERVICE_JWTSECRET=$(rand_hex 32)"
        echo "VIKUNJA_DATABASE_TYPE=sqlite"
        echo "VIKUNJA_DATABASE_PATH=/arena/data/vikunja.db"
        echo "VIKUNJA_FILES_BASEPATH=/arena/data/files"
    } > /arena/secrets/service.env
fi

/arena/restart.sh initial
/arena/facility.sh setup
exec /usr/sbin/sshd -D -e
