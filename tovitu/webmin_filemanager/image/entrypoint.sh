#!/usr/bin/env bash
set -euo pipefail

STATE=/var/lib/webmin-arena
EDITABLE=/srv/challenge/webmin

mkdir -p /run/sshd /srv/challenge "$STATE"
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi

if [ ! -d "$EDITABLE/acl" ]; then
    cp -a /opt/webmin-template "$EDITABLE"
    chown -R arena_agent:arena_agent "$EDITABLE"
    chmod -R a+rX,u+w "$EDITABLE"
fi

if [ ! -f "$STATE/initialized" ]; then
    cp -a /opt/webmin-config-seed/. /etc/webmin/
    cp -a /opt/webmin-var-seed/. /var/webmin/
    sed -i \
        -e "s#^root=.*#root=$EDITABLE#" \
        -e "s#^mimetypes=.*#mimetypes=$EDITABLE/mime.types#" \
        /etc/webmin/miniserv.conf
    umask 077
    printf 'WmAdm9!%s\n' "$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')" \
        > "$STATE/admin-password"
    "$EDITABLE/changepass.pl" /etc/webmin arena_admin "$(cat "$STATE/admin-password")"
    touch "$STATE/initialized"
fi

sed -i \
    -e "s#^root=.*#root=$EDITABLE#" \
    -e "s#^mimetypes=.*#mimetypes=$EDITABLE/mime.types#" \
    /etc/webmin/miniserv.conf
chown root:root "$STATE/admin-password" "$STATE/initialized"
chmod 0600 "$STATE/admin-password" "$STATE/initialized"
install -d -o root -g root -m 0700 "$STATE/proofs" "$STATE/releases"

/arena/restart.sh
exec /usr/sbin/sshd -D -e
