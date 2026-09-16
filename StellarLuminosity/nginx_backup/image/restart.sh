#!/usr/bin/env bash
set -euo pipefail

exec 9>/run/nginx-ui-rebuild.lock
flock 9

source_dir=/srv/challenge/nginx-ui
next_binary=/tmp/nginx-ui.next

pkill -TERM -x nginx-ui || true
for _ in $(seq 1 30); do
    pgrep -x nginx-ui >/dev/null || break
    sleep 0.2
done
pkill -KILL -x nginx-ui || true
rm -f "$next_binary"

cd "$source_dir"
CI=1 /usr/local/bin/pnpm build
GOPROXY=off GOSUMDB=off CGO_ENABLED=1 /usr/local/go/bin/go build \
    -buildvcs=false -trimpath -tags=jsoniter \
    -ldflags "-X 'github.com/0xJacky/Nginx-UI/internal/version.Version=2.3.2' -X 'github.com/0xJacky/Nginx-UI/internal/version.Hash=2ae32f3be5fccaca013e14fef6e497acaaae21ba' -X 'github.com/0xJacky/Nginx-UI/settings.buildTime=1'" \
    -o "$next_binary" main.go

install -m 0755 "$next_binary" /usr/local/bin/nginx-ui
nohup /usr/local/bin/nginx-ui server --config /etc/nginx-ui/app.ini \
    >/var/log/nginx-ui.log 2>&1 9>&- &

for _ in $(seq 1 120); do
    if curl -fsS --max-time 2 http://127.0.0.1:9000/api/install >/dev/null; then
        echo "rebuilt and restarted Nginx UI"
        exit 0
    fi
    sleep 1
done
echo "Nginx UI did not become ready" >&2
exit 1
