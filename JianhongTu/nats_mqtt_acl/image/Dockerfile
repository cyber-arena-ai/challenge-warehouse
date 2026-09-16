FROM --platform=linux/amd64 golang:1.25.8-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa

ARG SOURCE_URL=https://github.com/nats-io/nats-server/archive/73b3dd9a5ea0fa7bf08b702338676355b29b5fb4.tar.gz
ARG SOURCE_SHA256=d7b56fddf167fdff4de8c03d972d0616a0aed944f74c4d11700c3d55dc02f524

ENV GOMODCACHE=/opt/go/pkg/mod \
    GOCACHE=/opt/go/cache \
    GOTOOLCHAIN=local

COPY apks/ /tmp/apks/
RUN cd /tmp/apks \
    && sha256sum -c SHA256SUMS \
    && apk add --no-cache --no-network ./*.apk \
    && rm -rf /tmp/apks \
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
        -o /srv/runtime/nats-server . \
    && chown -R arena_agent:arena_agent /srv/challenge/nats-server \
    && chmod -R u+rwX,go+rX /srv/challenge/nats-server \
    && chown root:root /srv/runtime/nats-server \
    && chmod 0755 /srv/runtime/nats-server

COPY entrypoint.sh restart.sh facility.py /arena/
RUN mkdir -p /arena/secrets /arena/state /etc/nats /data/jetstream \
        /run/sshd /home/arena_agent/.ssh \
    && chown -R nats:nats /data /etc/nats \
    && chmod 0700 /arena/secrets /arena/state \
    && chown root:root /arena/entrypoint.sh /arena/restart.sh /arena/facility.py \
    && chmod 0555 /arena/entrypoint.sh /arena/restart.sh /arena/facility.py \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 1883 22
ENTRYPOINT []
CMD ["/arena/entrypoint.sh"]
