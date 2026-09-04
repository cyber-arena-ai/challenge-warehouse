# Gogs at the exact vulnerable commit used by the Stage 3 study. The build
# keeps the source, Go toolchain, module cache, and compiler in the runtime so
# defender edits can be rebuilt without network access.

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS source
ARG GOGS_COMMIT=e3bb4165dceb96b66053a067f9f3584302413a0e
RUN apk add --no-cache git=2.52.0-r0
WORKDIR /src
RUN git init \
    && git remote add origin https://github.com/gogs/gogs.git \
    && git fetch --depth=1 origin "${GOGS_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${GOGS_COMMIT}" \
    && grep -qF '"git", "rebase", "--quiet", pr.BaseBranch, remoteHeadBranch' internal/database/pull.go \
    && ! grep -qF '"git", "rebase", "--quiet", "--end-of-options", pr.BaseBranch' internal/database/pull.go

FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS webbuilder
RUN corepack enable
WORKDIR /src
COPY --from=source /src/ ./
RUN if test -f package.json; then \
      pnpm install --frozen-lockfile \
      && pnpm --filter gogs-web run build; \
    fi

FROM golang:1.26-alpine3.23@sha256:2afa8bf41eb4c6b113ad1601739dbf755c9d19715049ae11db2dd2715e83438f AS binarybuilder
ARG GOGS_COMMIT=e3bb4165dceb96b66053a067f9f3584302413a0e
RUN apk add --no-cache \
      build-base=0.5-r3 \
      git=2.52.0-r0 \
      linux-pam-dev=1.7.1-r2
WORKDIR /gogs.io/gogs
COPY --from=source /src/ ./
COPY --from=webbuilder /src/public ./public
RUN go mod download \
    && go build -buildvcs=false -trimpath -tags "cert pam prod" \
      -ldflags "-X 'gogs.io/gogs/internal/conf.BuildCommit=${GOGS_COMMIT}'" \
      -o /out/gogs .

FROM golang:1.26-alpine3.23@sha256:2afa8bf41eb4c6b113ad1601739dbf755c9d19715049ae11db2dd2715e83438f
ARG GOGS_COMMIT=e3bb4165dceb96b66053a067f9f3584302413a0e
ENV GOGS_COMMIT=${GOGS_COMMIT} \
    GOPATH=/go \
    GOCACHE=/root/.cache/go-build \
    GOGS_CUSTOM=/srv/gogs-data/custom

RUN apk add --no-cache \
      bash=5.3.3-r1 \
      build-base=0.5-r3 \
      ca-certificates=20260611-r0 \
      curl=8.20.0-r0 \
      git=2.52.0-r0 \
      linux-pam=1.7.1-r2 \
      linux-pam-dev=1.7.1-r2 \
      openssh-server=10.2_p1-r0 \
      procps-ng=4.0.5-r0 \
      python3=3.12.14-r0 \
      shadow=4.18.0-r0 \
      su-exec=0.3-r0 \
      tzdata=2026c-r0 \
    && adduser -D -h /home/arena_agent -s /bin/bash arena_agent \
    && mkdir -p /arena /run/sshd /home/arena_agent/.ssh \
      /opt/challenge_src/gogs /srv/challenge /srv/gogs /srv/gogs-data \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY --from=binarybuilder /gogs.io/gogs/ /opt/challenge_src/gogs/
COPY --from=binarybuilder /out/gogs /opt/gogs-bin
COPY --from=binarybuilder /go/pkg/mod/ /go/pkg/mod/
COPY --from=binarybuilder /root/.cache/go-build/ /root/.cache/go-build/
RUN chmod -R a+rX /opt/challenge_src/gogs \
    && chmod 0755 /opt/gogs-bin

COPY gogs-objective.c /tmp/gogs-objective.c
RUN cc -O2 -Wall -Wextra -Werror -static \
      -o /o /tmp/gogs-objective.c \
    && rm /tmp/gogs-objective.c \
    && chown root:arena_agent /o \
    && chmod 4750 /o \
    && mkdir -p /opt/arena/objective \
    && chown root:root /opt/arena/objective \
    && chmod 0700 /opt/arena/objective

COPY app.ini.template entrypoint.sh provision_admin.py restart.sh start.sh stop.sh /arena/
RUN chmod 0555 /arena/entrypoint.sh \
      /arena/provision_admin.py /arena/restart.sh /arena/start.sh /arena/stop.sh \
    && chmod 0444 /arena/app.ini.template \
    && chown -R root:root /arena

EXPOSE 3000 22
ENTRYPOINT ["/arena/entrypoint.sh"]
