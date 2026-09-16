#!/usr/bin/env bash
set -euo pipefail

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd /home/arena_agent/.ssh /srv/challenge
chown arena_agent:arena_agent /home/arena_agent/.ssh
chmod 0700 /home/arena_agent/.ssh

if [ ! -f /srv/challenge/openfire/pom.xml ]; then
    rm -rf /srv/challenge/openfire /srv/challenge/openfire.next \
        /srv/challenge/.m2 /srv/challenge/.m2.next
    cp -a /opt/challenge-source/openfire /srv/challenge/openfire.next
    mkdir -p /srv/challenge/.m2.next
    cp -a /opt/maven-repository /srv/challenge/.m2.next/repository
    mv /srv/challenge/openfire.next /srv/challenge/openfire
    mv /srv/challenge/.m2.next /srv/challenge/.m2
    chown -R arena_agent:arena_agent /srv/challenge
    chmod -R u+rwX /srv/challenge
fi
touch /run/openfire-arena-source-ready

if [ ! -s /var/lib/openfire-arena/admin-password ]; then
    password="Of9!$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
    printf '%s\n' "$password" > /var/lib/openfire-arena/admin-password
    chown root:root /var/lib/openfire-arena/admin-password
    chmod 0400 /var/lib/openfire-arena/admin-password
fi

exec /usr/sbin/sshd -D -e
