# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# Exact vulnerable Jenkins source plus its offline-rebuild Maven repository.
FROM --platform=linux/amd64 maven:3.9.11-eclipse-temurin-21@sha256:463a1849665463254b2dd56e3a5b316f1596bc93d0571065c06ea05bb48ab8f4 AS source-build

ARG PRIMARY_COMMIT=659b4380bf1829fcb114665618a9c665e329d0e0
ARG REPAIR_COMMIT=6dc99937605d5bddfeaae43a4cd14c2571e23adc

RUN git clone --filter=blob:none --no-checkout \
        https://github.com/jenkinsci/jenkins.git /verify \
    && git -C /verify fetch origin "${PRIMARY_COMMIT}" "${REPAIR_COMMIT}" \
    && test "$(git -C /verify rev-parse "${REPAIR_COMMIT}^")" = "${PRIMARY_COMMIT}" \
    && git init /src \
    && git -C /src remote add origin https://github.com/jenkinsci/jenkins.git \
    && git -C /src fetch --depth=1 origin "${PRIMARY_COMMIT}" \
    && git -C /src checkout --detach FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "${PRIMARY_COMMIT}" \
    && rm -rf /verify

WORKDIR /src
RUN git checkout --detach "${PRIMARY_COMMIT}" \
    && test "$(git rev-parse HEAD)" = "${PRIMARY_COMMIT}" \
    && mvn -am -pl war,bom -Pquick-build clean install \
    && install -D -m 0444 war/target/jenkins.war /opt/jenkins/jenkins.war

FROM --platform=linux/amd64 jenkins/jenkins@sha256:7c9c4b1a6b036a9b53a65e52fd447b97663148b59f77ef4737be6c6dd8517024

USER root
ARG DEBIAN_SNAPSHOT=20260824T000000Z
ENV DEBIAN_FRONTEND=noninteractive
ENV PRIMARY_COMMIT=659b4380bf1829fcb114665618a9c665e329d0e0

RUN sed -i \
        -e "s|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|" \
        -e "s|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|" \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419 \
        curl=8.14.1-2+deb13u4 \
        git=1:2.47.3-0+deb13u1 \
        openssh-server=1:10.0p1-7+deb13u4 \
        procps=2:4.0.4-9 \
        python3=3.13.5-1 \
        util-linux=2.41.5-0+deb13u1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && javac -version \
    && useradd --create-home --shell /bin/bash arena_agent \
    && useradd --create-home --shell /bin/bash jenkins_worker \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /home/jenkins_worker/agent \
        /arena /opt/challenge_src/jenkins /var/lib/cyberarena-private \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chown -R jenkins_worker:jenkins_worker /home/jenkins_worker \
    && chmod 0700 /home/arena_agent/.ssh /home/jenkins_worker \
        /var/lib/cyberarena-private \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --latest=false --plugin-file /usr/share/jenkins/ref/plugins.txt

COPY --from=source-build /opt/jenkins/jenkins.war /opt/jenkins/jenkins.war
COPY --from=source-build --chown=root:root \
    /src/ /opt/challenge_src/jenkins/source/
COPY --from=source-build --chown=root:root \
    /root/.m2/repository/ /opt/challenge_src/m2/repository/
COPY --from=source-build --chown=root:root \
    /root/.cache/node/corepack/ /opt/challenge_src/corepack/
COPY --from=source-build --chown=root:root \
    /src/.yarn/cache/ /opt/challenge_src/yarn-cache/
COPY --from=source-build /usr/share/maven/ /usr/share/maven/
RUN ln -sf /usr/share/maven/bin/mvn /usr/local/bin/mvn

COPY init.groovy /usr/share/jenkins/ref/init.groovy.d/10-arena.groovy
COPY service/ /opt/challenge_src/jenkins/
COPY entrypoint.sh start.sh stop.sh restart.sh rebuild.sh agent_supervisor.sh facility.py /arena/

RUN chmod 0500 /arena/entrypoint.sh /arena/start.sh /arena/stop.sh /arena/restart.sh \
        /arena/rebuild.sh /arena/agent_supervisor.sh /arena/facility.py \
    && chown -R root:root /arena /var/lib/cyberarena-private \
    && chmod 0500 /arena

LABEL org.opencontainers.image.source="https://github.com/jenkinsci/jenkins" \
      org.opencontainers.image.revision="${PRIMARY_COMMIT}" \
      cyberarena.build.maven-image="maven:3.9.11-eclipse-temurin-21@sha256:463a1849665463254b2dd56e3a5b316f1596bc93d0571065c06ea05bb48ab8f4" \
      cyberarena.build.debian-snapshot="${DEBIAN_SNAPSHOT}"

EXPOSE 8080 22
ENTRYPOINT ["/arena/entrypoint.sh"]
