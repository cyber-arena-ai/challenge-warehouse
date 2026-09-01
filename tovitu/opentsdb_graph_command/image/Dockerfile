FROM --platform=linux/amd64 eclipse-temurin@sha256:7cb1137d4a02aeb7ca85faae69c5f0720703936cbfb0b4af21067c73174f9b5e

ENV DEBIAN_FRONTEND=noninteractive \
    HBASE_HOME=/opt/hbase \
    HBASE_CONF_DIR=/opt/hbase/conf

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf automake ca-certificates curl gcc gnuplot-nox libc6-dev make openssh-server \
        procps python3 util-linux \
    && rm -f /usr/bin/wget \
    && ln -s /usr/bin/python3 /usr/local/bin/python \
    && rm -rf /var/lib/apt/lists/*

COPY opentsdb-22b27ea30a859a6dbdcd65fcdf61190d46e1b677.tar /tmp/opentsdb.tar
RUN echo "c55a1285582debb11fad5b9d11479c438617aa600aa1303031e1a7b2d46eba54  /tmp/opentsdb.tar" | sha256sum -c - \
    && mkdir -p /opt/challenge-template \
    && tar -xf /tmp/opentsdb.tar -C /opt/challenge-template \
    && rm /tmp/opentsdb.tar \
    && test "$(sha256sum /opt/challenge-template/opentsdb/src/tsd/GraphHandler.java | cut -d' ' -f1)" = \
        "6077890364f589aca816a4658c417167827e25ea641ce6c78b8f8f80a0e96283"

WORKDIR /opt/challenge-template/opentsdb
RUN ./build.sh

COPY ArenaAuthentication.java /tmp/arena-auth/src/arena/ArenaAuthentication.java
COPY proof.c /tmp/opentsdb-proof.c
RUN mkdir -p /tmp/arena-auth/classes/META-INF/services /opt/opentsdb-plugin \
    && classpath="$(find build/third_party -name '*.jar' -print | sort | paste -sd:):/opt/challenge-template/opentsdb/build/tsdb-2.4.1.jar" \
    && javac -source 7 -target 7 -cp "$classpath" -d /tmp/arena-auth/classes \
        /tmp/arena-auth/src/arena/ArenaAuthentication.java \
    && printf '%s\n' arena.ArenaAuthentication \
        > /tmp/arena-auth/classes/META-INF/services/net.opentsdb.auth.Authentication \
    && jar cf /opt/opentsdb-plugin/arena-auth.jar -C /tmp/arena-auth/classes . \
    && gcc -O2 -Wall -Wextra -o /opt/opentsdb-plugin/opentsdb-proof \
        /tmp/opentsdb-proof.c \
    && rm -rf /tmp/arena-auth /tmp/opentsdb-proof.c

RUN curl -fsSL https://archive.apache.org/dist/hbase/1.2.6/hbase-1.2.6-bin.tar.gz \
        -o /tmp/hbase.tar.gz \
    && echo "face6b85fc6d2d24ca0b4b81338de30763695b99bfb78b7176a4da7f2b1d355abf8c262fa7c2af59aacd9e0e8902f7a1026bce4e6cf979684f6e5644c53a2aa3  /tmp/hbase.tar.gz" \
        | sha512sum -c - \
    && tar -xzf /tmp/hbase.tar.gz -C /opt \
    && mv /opt/hbase-1.2.6 /opt/hbase \
    && rm /tmp/hbase.tar.gz

RUN useradd --create-home --shell /bin/bash arena_agent \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin opentsdb \
    && mkdir -p /run/sshd /run/opentsdb /var/lib/hbase/data /var/lib/hbase/zookeeper \
        /var/lib/opentsdb/cache /var/log/opentsdb /etc/opentsdb \
    && chown -R opentsdb:opentsdb /var/lib/opentsdb /var/log/opentsdb \
    && mkdir -p /home/arena_agent/.ssh \
    && chown root:opentsdb /opt/opentsdb-plugin/opentsdb-proof \
    && chmod 0550 /opt/opentsdb-plugin/opentsdb-proof \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY hbase-site.xml /opt/hbase/conf/hbase-site.xml
COPY opentsdb.conf /etc/opentsdb/opentsdb.conf
COPY entrypoint.sh restart.sh start-opentsdb.sh /arena/
RUN chmod 555 /arena/entrypoint.sh /arena/restart.sh /arena/start-opentsdb.sh \
    && chown root:root /arena/entrypoint.sh /arena/restart.sh /arena/start-opentsdb.sh \
    && chmod -R a-w /opt/challenge-template /opt/opentsdb-plugin

EXPOSE 4242 22
CMD ["/arena/entrypoint.sh"]
