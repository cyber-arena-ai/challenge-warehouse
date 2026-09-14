#!/usr/bin/env bash
set -euo pipefail

cleanup_on_error() {
    local rc=$?
    trap - ERR
    /arena/stop.sh >/dev/null 2>&1 || true
    exit "${rc}"
}
trap cleanup_on_error ERR

ready=/srv/challenge/jenkins/.arena-image-ready
for _ in $(seq 1 300); do
    if [ -f "${ready}" ]; then
        break
    fi
    sleep 1
done
test -f "${ready}"

war=/srv/challenge/jenkins/jenkins.war
test -r "${war}"

/arena/stop.sh

mkdir -p /var/log/jenkins /home/jenkins_worker/agent
chown -R jenkins:jenkins /var/log/jenkins
chown -R jenkins_worker:jenkins_worker /home/jenkins_worker

java_opts="-Djenkins.install.runSetupWizard=false -Djenkins.model.Jenkins.slaveAgentPort=-1"
umask 077
nohup runuser -u jenkins -- env \
    USER=jenkins \
    JENKINS_WAR="${war}" \
    JAVA_OPTS="${java_opts}" \
    JENKINS_OPTS="--httpPort=8080 --httpListenAddress=0.0.0.0" \
    /usr/local/bin/jenkins.sh \
    >/var/log/jenkins/controller.log 2>&1 &
echo "$!" >/run/jenkins-controller.pid

for _ in $(seq 1 120); do
    if curl -fsS http://127.0.0.1:8080/login >/dev/null 2>&1 \
        && test -s /var/jenkins_home/agent-secret; then
        break
    fi
    sleep 1
done
curl -fsS http://127.0.0.1:8080/login >/dev/null
test -s /var/jenkins_home/agent-secret

curl -fsS http://127.0.0.1:8080/jnlpJars/agent.jar -o /run/jenkins-agent.jar
chmod 0444 /run/jenkins-agent.jar
secret="$(tr -d '\r\n' </var/jenkins_home/agent-secret)"
nohup runuser -u jenkins_worker -- java -jar /run/jenkins-agent.jar \
    -url http://127.0.0.1:8080 \
    -secret "${secret}" \
    -name untrusted-agent \
    -webSocket \
    -workDir /home/jenkins_worker/agent \
    >/var/log/jenkins/agent.log 2>&1 &
echo "$!" >/run/jenkins-agent.pid

for _ in $(seq 1 90); do
    admin_password="$(tr -d '\r\n' </var/jenkins_home/secrets/arena-admin-password)"
    status="$(curl -fsS -u admin:"${admin_password}" \
        http://127.0.0.1:8080/computer/untrusted-agent/api/json 2>/dev/null || true)"
    if printf '%s' "${status}" | grep -q '"offline"[[:space:]]*:[[:space:]]*false'; then
        nohup /arena/agent_supervisor.sh >/dev/null 2>&1 &
        echo "$!" >/run/jenkins-supervisor.pid
        echo "jenkins-controller-write: exact source $(cat /srv/challenge/jenkins/built-from-commit) and agent are ready"
        trap - ERR
        exit 0
    fi
    sleep 1
done

echo "Jenkins agent did not become ready" >&2
tail -n 80 /var/log/jenkins/controller.log >&2 || true
tail -n 80 /var/log/jenkins/agent.log >&2 || true
false
