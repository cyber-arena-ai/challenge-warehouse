#!/usr/bin/env bash
set -euo pipefail

EDITABLE=/srv/challenge/webmin
PIDFILE=/var/webmin/miniserv.pid
LOG=/var/log/webmin.log
READY=/run/webmin-arena/miniserv.ready
STARTED_PID=

stop_pid() {
    local pid="$1"
    local state
    kill "$pid" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            return 0
        fi
        state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ' || true)
        [[ "$state" == Z* ]] && return 0
        sleep 0.25
    done
    kill -KILL "$pid" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            return 0
        fi
        state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ' || true)
        [[ "$state" == Z* ]] && return 0
        sleep 0.1
    done
    return 1
}

stop_pidfile() {
    local pid
    [ -s "$PIDFILE" ] || return 0
    pid=$(cat "$PIDFILE")
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    stop_pid "$pid"
}

restart_failed() {
    local status=$?
    trap - EXIT
    rm -f "$READY" "$READY.pending"
    if [[ "$STARTED_PID" =~ ^[0-9]+$ ]]; then
        stop_pid "$STARTED_PID" || true
    fi
    stop_pidfile || true
    rm -f "$PIDFILE"
    exit "$status"
}

rm -f "$READY" "$READY.pending"
trap restart_failed EXIT

stop_pidfile
rm -f "$PIDFILE" /var/webmin/stop-flag

test -f "$EDITABLE/miniserv.pl"
test -f "$EDITABLE/authentic-theme/extensions/file-manager/file-manager-lib.pl"
/usr/local/bin/perl /arena/release_broker.pl ensure
perl -c "$EDITABLE/miniserv.pl" >/tmp/webmin-miniserv-lint.log
PERL5LIB="$EDITABLE/authentic-theme/lib:$EDITABLE" \
    perl -c "$EDITABLE/authentic-theme/extensions/file-manager/file-manager-lib.pl" \
    >/tmp/webmin-filemanager-lint.log
sed -i \
    -e "s#^root=.*#root=$EDITABLE#" \
    -e "s#^mimetypes=.*#mimetypes=$EDITABLE/mime.types#" \
    /etc/webmin/miniserv.conf

touch "$LOG"
chmod 0600 "$LOG"
nohup env PERLLIB="$EDITABLE" \
    "$EDITABLE/miniserv.pl" --nofork /etc/webmin/miniserv.conf >"$LOG" 2>&1 &
STARTED_PID=$!

for _ in $(seq 1 45); do
    if perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(PeerAddr=>"127.0.0.1",PeerPort=>10000,Proto=>"tcp",Timeout=>2) or exit 1; print $s "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"; local $/; $b=<$s>; exit(index($b,"session_login") >= 0 ? 0 : 1)'; then
        install -o root -g root -m 0600 /dev/null "$READY.pending"
        mv -f "$READY.pending" "$READY"
        trap - EXIT
        echo "webmin-filemanager-execute: source validated and MiniServ replaced"
        exit 0
    fi
    sleep 1
done

tail -n 80 "$LOG"
exit 1
