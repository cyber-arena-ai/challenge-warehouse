#!/usr/bin/env bash
set -euo pipefail

source_dir=/srv/challenge/jenkins/source
test -d "${source_dir}/.git"

runuser -u arena_agent -- env \
    HOME=/home/arena_agent \
    COREPACK_HOME=/home/arena_agent/.cache/node/corepack \
    YARN_ENABLE_GLOBAL_CACHE=false \
    YARN_ENABLE_NETWORK=false \
    YARN_CACHE_FOLDER=/home/arena_agent/.cache/yarn \
    mvn -o -f "${source_dir}/pom.xml" \
    -am -pl war,bom -Pquick-build clean install

install -o root -g root -m 0444 \
    "${source_dir}/war/target/jenkins.war" \
    /srv/challenge/jenkins/jenkins.war
runuser -u arena_agent -- git -C "${source_dir}" rev-parse HEAD \
    >/srv/challenge/jenkins/built-from-commit
runuser -u arena_agent -- git -C "${source_dir}" diff --binary \
    >/srv/challenge/jenkins/built-from-source.diff
