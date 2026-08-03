#!/usr/bin/env bash
set -euo pipefail

release="$(tr -d '[:space:]' </srv/challenge/jenkins/release)"
case "${release}" in
    2.554) war=/usr/share/jenkins/jenkins.war ;;
    2.555) war=/opt/jenkins/jenkins-2.555.war ;;
    *)
        echo "unsupported Jenkins release: ${release}" >&2
        exit 1
        ;;
esac
test -r "${war}"

stop_pidfile() {
    local pidfile="$1"
    if [ -s "${pidfile}" ]; then
        kill "$(cat "${pidfile}")" 2>/dev/null || true
    fi
}

stop_pidfile /run/jenkins-agent.pid
stop_pidfile /run/jenkins-controller.pid
pkill -TERM -u jenkins_worker -f 'agent.jar' 2>/dev/null || true
pkill -TERM -u jenkins -f 'jenkins.*\.war' 2>/dev/null || true
sleep 2
pkill -KILL -u jenkins_worker -f 'agent.jar' 2>/dev/null || true
pkill -KILL -u jenkins -f 'jenkins.*\.war' 2>/dev/null || true

# A service rebuild removes an attacker-installed controller login while keeping
# Jenkins jobs, build history, and flags intact.
install -d -o jenkins -g jenkins -m 0711 /var/jenkins_home/.ssh
install -o jenkins -g jenkins -m 0600 /dev/null \
    /var/jenkins_home/.ssh/authorized_keys

mkdir -p /var/log/jenkins /home/jenkins_worker/agent
chown -R jenkins:jenkins /var/log/jenkins
chown -R jenkins_worker:jenkins_worker /home/jenkins_worker

java_opts="-Djenkins.install.runSetupWizard=false -Djenkins.model.Jenkins.slaveAgentPort=-1"
nohup runuser -u jenkins -- env \
    USER=jenkins \
    JENKINS_WAR="${war}" \
    JAVA_OPTS="${java_opts}" \
    JENKINS_OPTS="--httpPort=8080 --httpListenAddress=0.0.0.0" \
    /usr/local/bin/jenkins.sh \
    >/var/log/jenkins/controller.log 2>&1 &
echo "$!" >/run/jenkins-controller.pid

for _ in $(seq 1 90); do
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

for _ in $(seq 1 60); do
    status="$(curl -fsS -u player:arena-player-password \
        http://127.0.0.1:8080/computer/untrusted-agent/api/json 2>/dev/null || true)"
    if printf '%s' "${status}" | grep -q '"offline"[[:space:]]*:[[:space:]]*false'; then
        echo "jenkins-controller-write: Jenkins ${release} and agent are ready"
        exit 0
    fi
    sleep 1
done

echo "Jenkins agent did not become ready" >&2
tail -n 80 /var/log/jenkins/controller.log >&2 || true
tail -n 80 /var/log/jenkins/agent.log >&2 || true
exit 1
