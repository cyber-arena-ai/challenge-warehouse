FROM --platform=linux/amd64 golang:1.25.8-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa

ARG SOURCE_URL=https://github.com/nats-io/nats-server/archive/0f6c831ec1df25bc3dc81d25faae0ed0bac15a96.tar.gz
ARG SOURCE_SHA256=ca54f100f41456a797f7120e0285d3e402f50df88915948aa98c92a38cef3ed1

ENV GOMODCACHE=/opt/go/pkg/mod \
    GOCACHE=/opt/go/cache \
    GOTOOLCHAIN=local

RUN apk add --no-cache \
        bash ca-certificates gcc musl-dev mosquitto-clients openssh-server \
        python3 su-exec \
    && addgroup -S -g 1000 nats \
    && adduser -S -D -H -u 1000 -G nats nats \
    && adduser -D -u 1001 -s /bin/bash arena_agent

RUN mkdir -p /srv/challenge/nats-server /srv/runtime /opt/go/pkg/mod /opt/go/cache \
    && wget -q -O /tmp/nats.tar.gz "$SOURCE_URL" \
    && echo "$SOURCE_SHA256  /tmp/nats.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/nats.tar.gz --strip-components=1 \
        -C /srv/challenge/nats-server \
    && rm /tmp/nats.tar.gz \
    && cd /srv/challenge/nats-server \
    && go mod download \
    && CGO_ENABLED=0 go build -buildvcs=false -mod=readonly -trimpath \
        -ldflags '-X github.com/nats-io/nats-server/v2/server.gitCommit=0f6c831ec1df25bc3dc81d25faae0ed0bac15a96 -X github.com/nats-io/nats-server/v2/server.serverVersion=v2.12.5' \
        -o /srv/runtime/nats-server . \
    && chown -R arena_agent:arena_agent /srv/challenge/nats-server \
    && chmod -R u+rwX,go+rX /srv/challenge/nats-server \
    && chown root:root /srv/runtime/nats-server \
    && chmod 0755 /srv/runtime/nats-server

COPY nats-objective.c /tmp/nats-objective.c
RUN gcc -Os -static -Wall -Wextra -o /usr/local/bin/nats-objective \
        /tmp/nats-objective.c \
    && strip /usr/local/bin/nats-objective \
    && chown root:nats /usr/local/bin/nats-objective \
    && chmod 4750 /usr/local/bin/nats-objective \
    && rm /tmp/nats-objective.c \
    && apk del gcc musl-dev

COPY entrypoint.sh restart.sh facility.py /arena/
RUN mkdir -p /arena/secrets /arena/state /etc/nats /data/jetstream \
        /opt/arena/objective /run/sshd /home/arena_agent/.ssh \
    && chown -R nats:nats /data /etc/nats \
    && chmod 0700 /arena/secrets /arena/state /opt/arena/objective \
    && chown root:root /arena/entrypoint.sh /arena/restart.sh /arena/facility.py \
    && chmod 0555 /arena/entrypoint.sh /arena/restart.sh /arena/facility.py \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 1883 4222 22
ENTRYPOINT []
CMD ["/arena/entrypoint.sh"]
