#!/usr/bin/env bash
# Keep the inbound agent running, and restart it if it exits.
#
# Jenkins executes build steps as the same OS user that owns the agent process
# (jenkins_worker), so anything running on the agent shares its process
# ownership. Reap that user before respawning: durable-task keeps a build's shell
# alive across an agent disconnect, so leftovers would otherwise outlive the
# agent and interfere with its replacement. With the agent confirmed down,
# nothing still running as that user is legitimate.
#
# Runs as root. Started and stopped by /arena/restart.sh, which owns the
# deliberate stop during a release switch. Rationale lives in the challenge
# README, which is maintainer documentation and is not shipped here.
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
