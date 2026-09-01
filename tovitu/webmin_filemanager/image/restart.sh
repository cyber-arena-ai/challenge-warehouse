#!/usr/bin/env bash
set -euo pipefail

EDITABLE=/srv/challenge/webmin
PIDFILE=/var/webmin/miniserv.pid
LOG=/var/log/webmin.log

test -f "$EDITABLE/miniserv.pl"
test -f "$EDITABLE/authentic-theme/extensions/file-manager/file-manager-lib.pl"
perl -c "$EDITABLE/miniserv.pl" >/tmp/webmin-miniserv-lint.log
PERL5LIB="$EDITABLE/authentic-theme/lib:$EDITABLE" \
    perl -c "$EDITABLE/authentic-theme/extensions/file-manager/file-manager-lib.pl" \
    >/tmp/webmin-filemanager-lint.log
sed -i \
    -e "s#^root=.*#root=$EDITABLE#" \
    -e "s#^mimetypes=.*#mimetypes=$EDITABLE/mime.types#" \
    /etc/webmin/miniserv.conf

if [ -s "$PIDFILE" ]; then
    kill "$(cat "$PIDFILE")" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
        kill -0 "$(cat "$PIDFILE")" >/dev/null 2>&1 || break
        sleep 0.25
    done
    kill -KILL "$(cat "$PIDFILE")" >/dev/null 2>&1 || true
fi
rm -f "$PIDFILE" /var/webmin/stop-flag
touch "$LOG"
chmod 0600 "$LOG"
nohup env PERLLIB="$EDITABLE" \
    "$EDITABLE/miniserv.pl" --nofork /etc/webmin/miniserv.conf >"$LOG" 2>&1 &

for _ in $(seq 1 45); do
    if perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(PeerAddr=>"127.0.0.1",PeerPort=>10000,Proto=>"tcp",Timeout=>2) or exit 1; print $s "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"; local $/; $b=<$s>; exit(index($b,"session_login") >= 0 ? 0 : 1)'; then
        echo "webmin-filemanager-execute: source validated and MiniServ replaced"
        exit 0
    fi
    sleep 1
done

tail -n 80 "$LOG"
exit 1
