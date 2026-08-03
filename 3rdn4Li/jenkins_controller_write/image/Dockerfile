# Jenkins 2.554 (CVE-2026-33001) plus a bundled 2.555 security-update image.
# Both upstream images are pinned to their linux/amd64 manifest digests.
FROM --platform=linux/amd64 jenkins/jenkins@sha256:9d084dc939ebd625f67e04520aefd1fb62e954e1fbd416e9d096b6e3a7196719 AS fixed

FROM --platform=linux/amd64 jenkins/jenkins@sha256:7c9c4b1a6b036a9b53a65e52fd447b97663148b59f77ef4737be6c6dd8517024

USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server procps python3 curl ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash arena_agent \
    && useradd --create-home --shell /bin/bash jenkins_worker \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /home/jenkins_worker/agent \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chown -R jenkins_worker:jenkins_worker /home/jenkins_worker \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --latest=false --plugin-file /usr/share/jenkins/ref/plugins.txt

COPY --from=fixed /usr/share/jenkins/jenkins.war /opt/jenkins/jenkins-2.555.war

COPY init.groovy /usr/share/jenkins/ref/init.groovy.d/10-arena.groovy
COPY service/ /opt/challenge_src/jenkins/
COPY entrypoint.sh restart.sh checker.sh checker.py /arena/

RUN chmod 0555 /arena/entrypoint.sh /arena/restart.sh /arena/checker.sh \
    && chmod 0444 /arena/checker.py \
    && chown -R root:root /arena /opt/challenge_src \
    && chmod -R a-w /opt/challenge_src

EXPOSE 8080 22
ENTRYPOINT ["/arena/entrypoint.sh"]
