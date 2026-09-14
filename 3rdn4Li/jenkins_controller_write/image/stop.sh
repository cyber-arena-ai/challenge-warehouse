#!/usr/bin/env bash
set -euo pipefail

stop_pidfile() {
    local pidfile="$1"
    if [ -s "${pidfile}" ]; then
        kill "$(cat "${pidfile}")" 2>/dev/null || true
    fi
}

stop_pidfile /run/jenkins-supervisor.pid
pkill -TERM -f '/arena/agent_supervisor.sh' 2>/dev/null || true
stop_pidfile /run/jenkins-agent.pid
stop_pidfile /run/jenkins-controller.pid
pkill -TERM -u jenkins_worker -f 'agent.jar' 2>/dev/null || true
pkill -TERM -u jenkins -f 'jenkins.*\.war' 2>/dev/null || true

for _ in $(seq 1 20); do
    if ! pgrep -u jenkins_worker -f 'agent.jar' >/dev/null \
        && ! pgrep -u jenkins -f 'jenkins.*\.war' >/dev/null \
        && ! pgrep -f '/arena/agent_supervisor.sh' >/dev/null; then
        break
    fi
    sleep 1
done

pkill -KILL -f '/arena/agent_supervisor.sh' 2>/dev/null || true
pkill -KILL -u jenkins_worker -f 'agent.jar' 2>/dev/null || true
pkill -KILL -u jenkins -f 'jenkins.*\.war' 2>/dev/null || true
rm -f /run/jenkins-supervisor.pid /run/jenkins-agent.pid \
    /run/jenkins-controller.pid

if pgrep -u jenkins_worker -f 'agent.jar' >/dev/null \
    || pgrep -u jenkins -f 'jenkins.*\.war' >/dev/null \
    || pgrep -f '/arena/agent_supervisor.sh' >/dev/null \
    || timeout 1 bash -c '</dev/tcp/127.0.0.1/8080' 2>/dev/null; then
    echo "Jenkins generation did not stop" >&2
    exit 1
fi
