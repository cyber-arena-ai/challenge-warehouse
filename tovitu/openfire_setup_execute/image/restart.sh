#!/usr/bin/env bash
set -euo pipefail

SOURCE=/srv/challenge/openfire
DATA=/var/lib/openfire
RUNTIME=/usr/local/openfire
NEXT=/usr/local/openfire.next
LOG=/var/log/openfire
PID=/run/openfire-arena.pid

runuser -u arena_agent -- env HOME=/home/arena_agent \
    mvn -o -s /arena/settings.xml \
    -Dmaven.repo.local=/srv/challenge/.m2/repository \
    -DskipTests -f "$SOURCE/pom.xml" package
test -x "$SOURCE/distribution/target/distribution-base/bin/openfire.sh"

if [ -s "$PID" ]; then
    old_pid=$(cat "$PID")
    kill "$old_pid" 2>/dev/null || true
    for _ in $(seq 1 30); do
        kill -0 "$old_pid" 2>/dev/null || break
        sleep 0.25
    done
    kill -KILL "$old_pid" 2>/dev/null || true
    rm -f "$PID"
fi

rm -rf "$NEXT"
cp -a "$SOURCE/distribution/target/distribution-base" "$NEXT"
mv "$NEXT/conf" "$NEXT/conf_org"
mv "$NEXT/plugins" "$NEXT/plugins_org"
mv "$NEXT/resources/security" "$NEXT/resources/security_org"

mkdir -p "$DATA" "$LOG"
if [ ! -d "$DATA/conf" ]; then
    cp -a "$NEXT/conf_org" "$DATA/conf"
    cp -a "$NEXT/plugins_org" "$DATA/plugins"
    mkdir -p "$DATA/conf/security"
    cp -a "$NEXT/resources/security_org/." "$DATA/conf/security/"
fi
mkdir -p "$DATA/plugins" "$DATA/embedded-db"
rm -rf "$DATA/plugins/admin"
ln -s "$RUNTIME/plugins_org/admin" "$DATA/plugins/admin"

rm -rf "$NEXT/conf" "$NEXT/plugins" "$NEXT/resources/security" "$NEXT/embedded-db" "$NEXT/logs"
ln -s "$DATA/conf" "$NEXT/conf"
ln -s "$DATA/plugins" "$NEXT/plugins"
ln -s "$DATA/conf/security" "$NEXT/resources/security"
ln -s "$DATA/embedded-db" "$NEXT/embedded-db"
ln -s "$LOG" "$NEXT/logs"
chown -R openfire:openfire "$DATA" "$LOG"

rm -rf "$RUNTIME"
mv "$NEXT" "$RUNTIME"
chown -R root:root "$RUNTIME"
chown root:openfire "$RUNTIME"
chmod 0775 "$RUNTIME"

runuser -u openfire -- env OPENFIRE_HOME="$RUNTIME" HOME="$DATA" \
    "$RUNTIME/bin/openfire.sh" > "$LOG/stdout.log" 2>&1 &
echo $! > "$PID"

for _ in $(seq 1 120); do
    if curl -sS --max-time 2 -o /dev/null http://127.0.0.1:9090/; then
        echo "openfire-setup-execute: source built and Openfire started"
        exit 0
    fi
    if ! kill -0 "$(cat "$PID")" 2>/dev/null; then
        tail -n 80 "$LOG/stdout.log" >&2 || true
        exit 1
    fi
    sleep 1
done

tail -n 80 "$LOG/stdout.log" >&2 || true
exit 1
