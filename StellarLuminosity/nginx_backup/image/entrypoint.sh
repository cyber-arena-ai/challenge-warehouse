#!/usr/bin/env bash
set -euo pipefail

ssh-keygen -A >/dev/null 2>&1
mkdir -p /run/sshd /srv/challenge /srv/nginx-ui/private /etc/nginx-ui
chmod 0700 /srv/nginx-ui/private

if [ ! -d /srv/challenge/nginx-ui ]; then
    cp -a /opt/nginx-ui-source /srv/challenge/nginx-ui
fi
chown -R arena_agent:arena_agent /srv/challenge/nginx-ui

if [ ! -f /etc/nginx-ui/app.ini ]; then
    crypto_secret="$(openssl rand -hex 32)"
    cat > /etc/nginx-ui/app.ini <<EOF
[app]
PageSize = 20
JwtSecret =

[server]
Host = 0.0.0.0
Port = 9000
RunMode = release
EnableHTTPS = false
EnableH2 = false
EnableH3 = false

[database]
Name = database

[crypto]
Secret = ${crypto_secret}

[nginx]
ConfigDir = /etc/nginx
AccessLogPath = /var/log/nginx/access.log
ErrorLogPath = /var/log/nginx/error.log
TestConfigCmd = nginx -t
ReloadCmd = nginx -s reload

[node]
Name = Local
Secret =
SkipInstallation = false
Demo = false
EOF
    chmod 0600 /etc/nginx-ui/app.ini
fi

nohup /usr/local/bin/nginx-ui server --config /etc/nginx-ui/app.ini \
    >/var/log/nginx-ui.log 2>&1 &

for _ in $(seq 1 120); do
    if curl -fsS --max-time 2 http://127.0.0.1:9000/api/install >/dev/null; then
        break
    fi
    sleep 1
done
curl -fsS --max-time 2 http://127.0.0.1:9000/api/install >/dev/null
python3 /arena/provision.py
touch /run/nginx-ui-arena-ready

exec /usr/sbin/sshd -D -e
