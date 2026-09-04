FROM --platform=linux/amd64 maven@sha256:8d3b35643e52d707b16a3e9b52698be1b75c2b45beb5d0e37d35e881f0a18ced AS geotools

ARG GEOTOOLS_COMMIT=c8a398e0554f29b55276892cbe4025f68fb4aaea

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /srv/challenge/geotools \
    && git -C /srv/challenge/geotools init \
    && git -C /srv/challenge/geotools remote add origin \
       https://github.com/geotools/geotools.git \
    && git -C /srv/challenge/geotools fetch --depth 1 origin "$GEOTOOLS_COMMIT" \
    && git -C /srv/challenge/geotools checkout --detach FETCH_HEAD \
    && test "$(git -C /srv/challenge/geotools rev-parse HEAD)" = "$GEOTOOLS_COMMIT" \
    && rm -rf /srv/challenge/geotools/.git

RUN cd /srv/challenge/geotools \
    && mvn -B -DskipTests \
       -pl :gt-main,:gt-xsd-core,:gt-app-schema -am package


FROM --platform=linux/amd64 docker.osgeo.org/geoserver@sha256:c210398100dcefdb3de3a7ebe7d1c5068aa92ce6e490aebdeaa3c51a79c1eb57

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl gcc libc6-dev openssh-server procps python3 util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 geoserver \
    && useradd --uid 1000 --gid 1000 --home-dir /opt/geoserver_home \
       --create-home --shell /usr/sbin/nologin geoserver \
    && useradd --uid 1001 --create-home --shell /bin/bash \
       --groups geoserver arena_agent

COPY --from=geotools /usr/share/maven /usr/share/maven
COPY --from=geotools /root/.m2/repository /opt/maven/repository
COPY --from=geotools /srv/challenge/geotools /srv/challenge/geotools

ENV MAVEN_HOME=/usr/share/maven \
    MAVEN_CONFIG=/opt/maven \
    PATH=/usr/share/maven/bin:$PATH \
    GEOSERVER_DATA_DIR=/opt/geoserver_data \
    HOME=/opt/geoserver_home

COPY geoserver-objective.c /tmp/geoserver-objective.c
RUN gcc -O2 -Wall -Wextra -static \
       -o /usr/local/bin/geoserver-objective /tmp/geoserver-objective.c \
    && strip /usr/local/bin/geoserver-objective \
    && rm /tmp/geoserver-objective.c

COPY entrypoint.sh service-control.sh restart.sh facility.py /arena/

RUN test -x /opt/startup.sh \
    && test -x /opt/apache-tomcat-9.0.86/bin/catalina.sh \
    && test -d /opt/apache-tomcat-9.0.86/webapps/geoserver/WEB-INF/lib \
    && test -d /opt/geoserver_data \
    && mvn --version >/dev/null \
    && mkdir -p /arena/secrets /arena/state /opt/arena/objective \
       /run/geoserver /run/sshd /home/arena_agent/.ssh \
    && chown -R geoserver:geoserver \
       /opt/apache-tomcat-9.0.86 /opt/geoserver_data /opt/geoserver_home \
    && chown -R arena_agent:geoserver /srv/challenge/geotools \
    && chmod -R ug+rwX /srv/challenge/geotools \
    && chown root:geoserver /usr/local/bin/geoserver-objective \
    && chmod 4750 /usr/local/bin/geoserver-objective \
    && chmod 0700 /arena/secrets /arena/state /opt/arena/objective \
    && chown root:root /arena/entrypoint.sh /arena/service-control.sh \
       /arena/restart.sh /arena/facility.py \
    && chmod 0555 /arena/entrypoint.sh /arena/service-control.sh \
       /arena/restart.sh /arena/facility.py \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' \
       /etc/ssh/sshd_config

HEALTHCHECK --interval=15s --timeout=10s --start-period=150s --retries=3 \
    CMD test -f /run/geoserver/arena.ready \
        && curl -fsS 'http://127.0.0.1:8080/geoserver/wfs?service=WFS&version=2.0.0&request=GetCapabilities' \
           -o /dev/null || exit 1

EXPOSE 8080 22
ENTRYPOINT []
CMD ["/arena/entrypoint.sh"]
