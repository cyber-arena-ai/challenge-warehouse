#!/usr/bin/env bash
# Keep the inbound agent alive.
#
# Build steps execute as the same OS user that owns the agent process
# (jenkins_worker), because that is simply how Jenkins runs them — the agent JVM
# spawns them as itself. The scoped maintainer must be able to run commands on
# the agent for the intended attack to exist at all, so they can also signal that
# agent dead. One `sh 'pkill -f agent.jar'` takes the whole service down with no
# vulnerability involved, on the patched release too.
#
# Respawning alone would not settle it: durable-task deliberately keeps a build's
# shell alive across an agent disconnect, so a killer loop outlives the agent it
# killed and would just re-kill the replacement. Hence the reap — with the agent
# confirmed down, nothing still running as jenkins_worker is legitimate, so the
# whole user is cleared before a fresh agent is started.
#
# Runs as root so the attacker cannot signal it. Started and stopped by
# /arena/restart.sh, which owns the deliberate stop during a release switch.
set -uo pipefail

POLL_SECS="${AGENT_SUPERVISOR_POLL:-3}"
SETTLE_SECS="${AGENT_SUPERVISOR_SETTLE:-5}"
LOG=/var/log/jenkins/supervisor.log

log() { echo "$(date -Is) $*" >>"${LOG}"; }

agent_alive() { pgrep -u jenkins_worker -f 'agent.jar' >/dev/null 2>&1; }

controller_alive() { curl -fsS -o /dev/null http://127.0.0.1:8080/login 2>/dev/null; }

spawn_agent() {
    local secret
    secret="$(tr -d '\r\n' </var/jenkins_home/agent-secret 2>/dev/null)" || return 1
    [ -n "${secret}" ] || return 1
    [ -r /run/jenkins-agent.jar ] || return 1

    mkdir -p /home/jenkins_worker/agent
    chown -R jenkins_worker:jenkins_worker /home/jenkins_worker

    nohup runuser -u jenkins_worker -- java -jar /run/jenkins-agent.jar \
        -url http://127.0.0.1:8080 \
        -secret "${secret}" \
        -name untrusted-agent \
        -webSocket \
        -workDir /home/jenkins_worker/agent \
        >>/var/log/jenkins/agent.log 2>&1 &
    echo "$!" >/run/jenkins-agent.pid
}

mkdir -p /var/log/jenkins
log "supervisor started (poll=${POLL_SECS}s)"

while true; do
    if ! agent_alive; then
        # Never fight a controller that is genuinely down — a killed controller
        # must stay visibly down for the health probe; /arena/restart.sh is the
        # only sanctioned way back.
        if controller_alive; then
            log "agent down; reaping jenkins_worker and respawning"
            pkill -KILL -u jenkins_worker 2>/dev/null || true
            sleep 1
            if spawn_agent; then
                sleep "${SETTLE_SECS}"
            else
                log "respawn prerequisites missing; will retry"
            fi
        fi
    fi
    sleep "${POLL_SECS}"
done
