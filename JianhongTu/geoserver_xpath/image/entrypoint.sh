#!/usr/bin/env bash
set -euo pipefail

trap '' HUP
rm -f /run/geoserver/arena.ready
mkdir -p /run/geoserver /run/sshd
ssh-keygen -A
/usr/sbin/sshd

/arena/service-control.sh start
/arena/service-control.sh ready
/arena/facility.py bootstrap
/arena/service-control.sh restart
/arena/service-control.sh ready
/arena/facility.py verify-bootstrap
touch /run/geoserver/arena.ready

trap '/arena/service-control.sh stop; exit 0' TERM INT
while true; do
    sleep 5 &
    wait $!
done
