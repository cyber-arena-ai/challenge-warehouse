FROM --platform=linux/amd64 golang:1.25.1-alpine@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd AS build

ARG CADDY_SOURCE_URL=https://github.com/caddyserver/caddy/archive/6610e2f1bd8f54853006eefd3849c9965190e57f.tar.gz
ARG CADDY_SOURCE_SHA256=5b7c743ed98af1cf27636667ec9a0f07b12fdc396c8018b3b6af2c439377d482

ENV GOMODCACHE=/go/pkg/mod \
    GOCACHE=/go/cache \
    GOTOOLCHAIN=local

RUN apk add --no-cache build-base ca-certificates curl \
    && mkdir -p /src /go/pkg/mod /go/cache \
    && curl -fsSL -o /tmp/caddy.tar.gz "$CADDY_SOURCE_URL" \
    && echo "$CADDY_SOURCE_SHA256  /tmp/caddy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/caddy.tar.gz --strip-components=1 -C /src \
    && rm /tmp/caddy.tar.gz

WORKDIR /src
RUN go mod download \
    && CGO_ENABLED=0 go build -buildvcs=false -mod=readonly -trimpath \
       -ldflags '-X github.com/caddyserver/caddy/v2.CustomVersion=v2.11.1' \
       -o /out/caddy ./cmd/caddy

COPY caddy-objective.c /tmp/caddy-objective.c
RUN cc -static -Os -Wall -Wextra -o /out/caddy-objective \
        /tmp/caddy-objective.c \
    && strip /out/caddy-objective

FROM --platform=linux/amd64 nextcloud:32.0.13-fpm-alpine@sha256:f19381ecfdd8cce20118e851f4958b011649a85e07e52d96eb9358bb55696ec6

ARG USER_SAML_URL=https://github.com/nextcloud-releases/user_saml/releases/download/v8.2.1/user_saml-v8.2.1.tar.gz
ARG USER_SAML_SHA256=68ed30dafe018783c27bdd3f82cc85221629774700e01f625a96635daad37d9b
ARG GROUPFOLDERS_URL=https://github.com/nextcloud-releases/groupfolders/releases/download/v20.1.18/groupfolders-v20.1.18.tar.gz
ARG GROUPFOLDERS_SHA256=3461a18dc0a073388aa48b6412873d02f040b3e7f3789f422ea8fab9cb812733

ENV PATH=/usr/local/go/bin:$PATH \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/go/cache \
    GOTOOLCHAIN=local

RUN apk add --no-cache \
        bash ca-certificates curl openssh-server procps python3 su-exec \
    && addgroup -S -g 1000 service \
    && adduser -S -D -H -u 1000 -G service service \
    && adduser -D -u 1001 -s /bin/bash arena_agent

RUN mkdir -p /usr/src/nextcloud/custom_apps \
    && curl -fsSL -o /tmp/user_saml.tar.gz "$USER_SAML_URL" \
    && echo "$USER_SAML_SHA256  /tmp/user_saml.tar.gz" | sha256sum -c - \
    && curl -fsSL -o /tmp/groupfolders.tar.gz "$GROUPFOLDERS_URL" \
    && echo "$GROUPFOLDERS_SHA256  /tmp/groupfolders.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/user_saml.tar.gz -C /usr/src/nextcloud/custom_apps \
    && tar -xzf /tmp/groupfolders.tar.gz -C /usr/src/nextcloud/custom_apps \
    && rm /tmp/user_saml.tar.gz /tmp/groupfolders.tar.gz

COPY --from=build /usr/local/go /usr/local/go
COPY --from=build /go/pkg/mod /go/pkg/mod
COPY --from=build /go/cache /go/cache
COPY --from=build /src /srv/challenge/caddy
COPY --from=build /out/caddy /srv/runtime/caddy
COPY --from=build /out/caddy-objective /usr/local/bin/caddy-objective
COPY php-fpm-service.conf /usr/local/etc/php-fpm.d/zzzz-arena.conf
COPY entrypoint.sh restart.sh facility.py /arena/

RUN mkdir -p /arena/secrets /arena/state /etc/caddy /opt/arena/objective \
        /run/caddy /run/sshd /srv/runtime /tmp/caddy-config /tmp/caddy-data \
        /home/arena_agent/.ssh \
    && chown -R arena_agent:arena_agent /srv/challenge/caddy \
    && chmod -R u+rwX,go+rX /srv/challenge/caddy \
    && chown root:root /srv/runtime/caddy \
    && chmod 0755 /srv/runtime/caddy \
    && chown root:service /usr/local/bin/caddy-objective \
    && chmod 4750 /usr/local/bin/caddy-objective \
    && chown -R service:service /run/caddy /tmp/caddy-config /tmp/caddy-data \
    && chmod 0700 /arena/secrets /arena/state /opt/arena/objective \
    && chown root:root /arena/entrypoint.sh /arena/restart.sh /arena/facility.py \
       /usr/local/etc/php-fpm.d/zzzz-arena.conf \
    && chmod 0555 /arena/entrypoint.sh /arena/restart.sh /arena/facility.py \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 8080 22
ENTRYPOINT []
CMD ["/arena/entrypoint.sh"]
