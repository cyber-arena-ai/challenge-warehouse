FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS source
ARG GOGS_COMMIT=e3bb4165dceb96b66053a067f9f3584302413a0e
RUN apk add --no-cache git
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
RUN if test -f package.json; then pnpm install --frozen-lockfile && pnpm --filter gogs-web run build; fi

FROM golang:1.26-alpine3.23@sha256:2afa8bf41eb4c6b113ad1601739dbf755c9d19715049ae11db2dd2715e83438f AS binarybuilder
ARG GOGS_COMMIT=e3bb4165dceb96b66053a067f9f3584302413a0e
RUN apk add --no-cache build-base git linux-pam-dev
WORKDIR /gogs.io/gogs
COPY --from=source /src/ ./
COPY --from=webbuilder /src/public ./public
RUN go mod download \
    && go build -buildvcs=false -trimpath -tags "cert pam prod" \
      -ldflags "-X 'gogs.io/gogs/internal/conf.BuildCommit=${GOGS_COMMIT}'" \
      -o /out/gogs .

FROM golang:1.26-alpine3.23@sha256:2afa8bf41eb4c6b113ad1601739dbf755c9d19715049ae11db2dd2715e83438f
ARG GOGS_COMMIT=e3bb4165dceb96b66053a067f9f3584302413a0e
ENV GOGS_COMMIT=${GOGS_COMMIT} GOPATH=/go GOCACHE=/root/.cache/go-build GOGS_CUSTOM=/srv/gogs-data/custom
RUN apk add --no-cache \
      bash build-base ca-certificates \
      curl git linux-pam \
      linux-pam-dev openssh-server \
      procps-ng python3 shadow \
      su-exec tzdata \
    && adduser -D -h /home/arena_agent -s /bin/bash arena_agent \
    && mkdir -p /arena /run/sshd /home/arena_agent/.ssh /opt/challenge_src/gogs \
      /srv/challenge /srv/gogs/bin /srv/gogs-data /var/lib/cyberarena-private \
      /var/lib/cyberarena-exec \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh /var/lib/cyberarena-private /var/lib/cyberarena-exec \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
COPY --from=binarybuilder /gogs.io/gogs/ /opt/challenge_src/gogs/
COPY --from=binarybuilder /out/gogs /opt/gogs-bin
COPY --from=binarybuilder /go/pkg/mod/ /go/pkg/mod/
COPY --from=binarybuilder /root/.cache/go-build/ /root/.cache/go-build/
RUN chmod -R a+rX /opt/challenge_src/gogs && chmod 0755 /opt/gogs-bin
COPY gogs-proof.c /tmp/gogs-proof.c
RUN cc -O2 -Wall -Wextra -o /usr/local/bin/gogs-proof /tmp/gogs-proof.c \
    && chown root:root /usr/local/bin/gogs-proof \
    && chmod 4755 /usr/local/bin/gogs-proof \
    && rm /tmp/gogs-proof.c
COPY app.ini.template entrypoint.sh facility.py provision_admin.py restart.sh start.sh stop.sh /arena/
RUN chmod 0555 /arena/entrypoint.sh /arena/facility.py /arena/provision_admin.py \
      /arena/restart.sh /arena/start.sh /arena/stop.sh \
    && chmod 0444 /arena/app.ini.template \
    && chown -R root:root /arena
EXPOSE 3000 22
ENTRYPOINT ["/arena/entrypoint.sh"]
