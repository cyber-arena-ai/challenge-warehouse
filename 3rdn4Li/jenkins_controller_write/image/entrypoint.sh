#!/usr/bin/env bash
set -euo pipefail

ready=/srv/challenge/jenkins/.arena-image-ready
if [ ! -e "${ready}" ]; then
    rm -rf /srv/challenge/jenkins /home/arena_agent/.m2 \
        /home/arena_agent/.cache/node/corepack /home/arena_agent/.cache/yarn
    mkdir -p /srv/challenge/jenkins /home/arena_agent/.cache/node
    cp -a /opt/challenge_src/jenkins/. /srv/challenge/jenkins/
    git -C /srv/challenge/jenkins/source checkout --detach "${PRIMARY_COMMIT}"
    test "$(git -C /srv/challenge/jenkins/source rev-parse HEAD)" = "${PRIMARY_COMMIT}"
    install -o root -g root -m 0444 /opt/jenkins/jenkins.war \
        /srv/challenge/jenkins/jenkins.war
    printf '%s\n' "${PRIMARY_COMMIT}" >/srv/challenge/jenkins/built-from-commit
    cp -a /opt/challenge_src/m2/. /home/arena_agent/.m2/
    cp -a /opt/challenge_src/corepack /home/arena_agent/.cache/node/corepack
    cp -a /opt/challenge_src/yarn-cache /home/arena_agent/.cache/yarn
    chown -R arena_agent:arena_agent /srv/challenge/jenkins/source \
        /home/arena_agent/.m2 /home/arena_agent/.cache
    install -o root -g root -m 0444 /dev/null "${ready}"
fi

ssh-keygen -A >/dev/null 2>&1
mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e
