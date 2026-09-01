#!/usr/bin/env bash
set -euo pipefail

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
mkdir -p /run/sshd /run/opentsdb /etc/opentsdb

if [ ! -f /srv/challenge/opentsdb/src/tsd/GraphHandler.java ]; then
    mkdir -p /srv/challenge/opentsdb
    cp -a /opt/challenge-template/opentsdb/. /srv/challenge/opentsdb/
    chown -R arena_agent:arena_agent /srv/challenge/opentsdb
    chmod -R a+rX,u+w /srv/challenge/opentsdb
fi

if [ ! -f /etc/opentsdb/principals.conf ]; then
    bootstrap_token="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
    printf 'player-bootstrap=arena-%s\n' "${bootstrap_token}" \
        > /etc/opentsdb/principals.conf
fi
chown root:opentsdb /etc/opentsdb/principals.conf
chmod 640 /etc/opentsdb/principals.conf

if ! pgrep -f 'org.apache.hadoop.hbase.master.HMaster' >/dev/null; then
    nohup /opt/hbase/bin/hbase master start > /var/log/opentsdb/hbase.log 2>&1 &
fi

hbase_ready=0
for _ in $(seq 1 90); do
    if output="$(echo status | /opt/hbase/bin/hbase shell -n 2>/dev/null)" \
        && grep -q '1 active master' <<<"${output}"; then
        hbase_ready=1
        break
    fi
    sleep 1
done
if [ "${hbase_ready}" != "1" ]; then
    echo "OpenTSDB challenge: HBase failed to become ready" >&2
    tail -n 80 /var/log/opentsdb/hbase.log >&2 || true
    exit 1
fi

if ! echo "exists 'tsdb'" | /opt/hbase/bin/hbase shell -n 2>/dev/null | grep -q 'true'; then
    HBASE_HOME=/opt/hbase COMPRESSION=NONE TSDB_TTL=2147483647 \
        sh /srv/challenge/opentsdb/src/create_table.sh >/var/log/opentsdb/create-table.log 2>&1
fi

/arena/start-opentsdb.sh
exec /usr/sbin/sshd -D -e
