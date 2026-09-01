FROM maven:3.9.9-eclipse-temurin-11@sha256:8d3b35643e52d707b16a3e9b52698be1b75c2b45beb5d0e37d35e881f0a18ced AS builder

USER root
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yqq --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY source-openfire.tar.gz /tmp/source-openfire.tar.gz
COPY libidn-1.35.jar /tmp/libidn-1.35.jar
COPY search-1.7.3-openfire-plugin-assembly.jar /tmp/search.jar
COPY settings.xml /tmp/settings.xml
RUN printf '%s  %s\n' \
      cbeeb94261b4754774733fb33d54b9a49fc41d6cf3ce4d7afa43e4d65c140f82 /tmp/source-openfire.tar.gz \
      0d10e225f6ff4fddc4aa373a4187b021ba35387338261969ebdcfbcb51058942 /tmp/libidn-1.35.jar \
      45d14b43e53438e3d798656e1fab07dff2233f2dade5a79504f4a0c332ec0f94 /tmp/search.jar \
      | sha256sum -c -

RUN mkdir -p /build /root/.m2/repository/org/gnu/inet/libidn/1.35 \
      /root/.m2/repository/org/igniterealtime/openfire/plugins/search/1.7.3 \
    && tar -xzf /tmp/source-openfire.tar.gz -C /build \
    && cp /tmp/libidn-1.35.jar /root/.m2/repository/org/gnu/inet/libidn/1.35/libidn-1.35.jar \
    && printf '%s\n' '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>org.gnu.inet</groupId><artifactId>libidn</artifactId><version>1.35</version></project>' \
      > /root/.m2/repository/org/gnu/inet/libidn/1.35/libidn-1.35.pom \
    && cp /tmp/search.jar /root/.m2/repository/org/igniterealtime/openfire/plugins/search/1.7.3/search-1.7.3-openfire-plugin-assembly.jar \
    && printf '%s\n' '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>org.igniterealtime.openfire.plugins</groupId><artifactId>search</artifactId><version>1.7.3</version></project>' \
      > /root/.m2/repository/org/igniterealtime/openfire/plugins/search/1.7.3/search-1.7.3.pom

WORKDIR /build/openfire
RUN mvn -s /tmp/settings.xml -Dmaven.repo.local=/root/.m2/repository -DskipTests package

COPY proof.c /tmp/proof.c
RUN gcc -O2 -Wall -Wextra -static -s -o /openfire-proof /tmp/proof.c


FROM maven:3.9.9-eclipse-temurin-11@sha256:8d3b35643e52d707b16a3e9b52698be1b75c2b45beb5d0e37d35e881f0a18ced

ENV OPENFIRE_HOME=/usr/local/openfire \
    OPENFIRE_DATA_DIR=/var/lib/openfire

RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yqq --no-install-recommends \
       openssh-server procps sudo curl ca-certificates python3 \
    && groupadd --system openfire \
    && useradd --system --gid openfire --home-dir /var/lib/openfire --shell /usr/sbin/nologin openfire \
    && useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /srv/challenge /var/log/openfire /var/lib/openfire-arena \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh /srv/challenge \
    && chmod 0700 /home/arena_agent/.ssh \
    && chmod 0700 /var/lib/openfire-arena \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /openfire-proof /usr/local/bin/openfire-proof
RUN chown root:openfire /usr/local/bin/openfire-proof && chmod 4750 /usr/local/bin/openfire-proof

COPY --from=builder /build/openfire /opt/challenge-source/openfire
COPY --from=builder /build/openfire/distribution/target/distribution-base /opt/openfire-distribution
COPY --from=builder /root/.m2/repository /opt/maven-repository
COPY settings.xml /arena/settings.xml
COPY restart.sh /arena/restart.sh
COPY entrypoint.sh /arena/entrypoint.sh
COPY facility_client.py /arena/facility_client.py
RUN chmod 0555 /arena/restart.sh /arena/entrypoint.sh /arena/facility_client.py \
    && chown root:root /arena/restart.sh /arena/entrypoint.sh /arena/facility_client.py /arena/settings.xml \
    && chmod -R a-w /opt/challenge-source /opt/openfire-distribution /opt/maven-repository

EXPOSE 22 5222 9090
ENTRYPOINT ["/arena/entrypoint.sh"]
