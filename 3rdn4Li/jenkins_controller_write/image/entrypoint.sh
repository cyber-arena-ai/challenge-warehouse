#!/usr/bin/env bash
set -euo pipefail

if [ ! -e /srv/challenge/jenkins/release ]; then
    mkdir -p /srv/challenge/jenkins
    cp -a /opt/challenge_src/jenkins/. /srv/challenge/jenkins/
    chown -R arena_agent:arena_agent /srv/challenge/jenkins
    chmod -R a+rX,u+w /srv/challenge/jenkins
fi

ssh-keygen -A >/dev/null 2>&1
mkdir -p /run/sshd /var/jenkins_home/.ssh
if [ ! -e /var/jenkins_home/.ssh/authorized_keys ]; then
    install -o jenkins -g jenkins -m 0600 /dev/null \
        /var/jenkins_home/.ssh/authorized_keys
fi
chown jenkins:jenkins /var/jenkins_home/.ssh
chmod 0711 /var/jenkins_home/.ssh

exec /usr/sbin/sshd -D -e
