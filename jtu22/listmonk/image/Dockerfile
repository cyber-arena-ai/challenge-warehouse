# Exact Listmonk e3499cf with full UI, co-resident PostgreSQL, and offline rebuild.
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS source
COPY source-primary.tar.gz /tmp/source-primary.tar.gz
RUN echo "29338f1a07e6526da8ac64922f237d6a906cd4542e6d8a9c151b60375d71dba0  /tmp/source-primary.tar.gz" | sha256sum -c - \
 && mkdir -p /src/listmonk \
 && tar -xzf /tmp/source-primary.tar.gz --strip-components=1 -C /src/listmonk \
 && test "$(head -n1 /src/listmonk/VERSION)" = "e3499cf72" \
 && rm /tmp/source-primary.tar.gz

FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS frontend-deps
WORKDIR /deps/frontend
COPY --from=source /src/listmonk/frontend/package.json /src/listmonk/frontend/yarn.lock ./
RUN corepack enable && yarn install --frozen-lockfile --ignore-scripts
WORKDIR /deps/frontend/email-builder
COPY --from=source /src/listmonk/frontend/email-builder/package.json /src/listmonk/frontend/email-builder/yarn.lock ./
RUN yarn install --frozen-lockfile

FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS frontend
WORKDIR /src/listmonk
COPY --from=source /src/listmonk/ ./
COPY --from=frontend-deps /root/.cache/node/corepack/ /root/.cache/node/corepack/
COPY --from=frontend-deps /deps/frontend/node_modules/ ./frontend/node_modules/
COPY --from=frontend-deps /deps/frontend/email-builder/node_modules/ ./frontend/email-builder/node_modules/
RUN --network=none corepack enable \
 && cp frontend/node_modules/altcha/dist/altcha.umd.cjs static/public/static/altcha.umd.js \
 && cd frontend/email-builder \
 && yarn build \
 && mkdir -p ../public/static/email-builder \
 && cp -r dist/. ../public/static/email-builder/ \
 && cd .. \
 && yarn build

FROM golang:1.26-alpine3.23@sha256:33ce311e5eecedee48ec1b84419c1306e9fbd71009f0d5c3f2a6904b579c1ecc AS go-deps
WORKDIR /src/listmonk
COPY --from=source /src/listmonk/go.mod /src/listmonk/go.sum ./
RUN go mod download

FROM go-deps AS builder
COPY --from=source /src/listmonk/ ./
COPY --from=frontend /src/listmonk/frontend/dist/ ./frontend/dist/
RUN --network=none CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/listmonk ./cmd

FROM postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73
USER root
RUN apk add --no-cache \
      bash=5.3.9-r1 ca-certificates=20260611-r0 curl=8.22.0-r0 \
      git=2.54.0-r0 openssh=10.3_p1-r1 procps-ng=4.0.6-r0 \
      su-exec=0.3-r0 \
 && adduser -D -s /bin/bash arena_agent \
 && mkdir -p /run/sshd /home/arena_agent/.ssh /arena /etc/listmonk \
      /opt/challenge_src/listmonk /srv/challenge /srv/listmonk/private \
 && chown arena_agent:arena_agent /home/arena_agent/.ssh \
 && chmod 0700 /home/arena_agent/.ssh \
 && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY --from=go-deps /usr/local/go /usr/local/go
COPY --from=go-deps /go/pkg/mod /go/pkg/mod
COPY --from=source /src/listmonk/ /opt/challenge_src/listmonk/
COPY --from=frontend /src/listmonk/frontend/dist/ /opt/challenge_src/listmonk/frontend/dist/
COPY --from=builder /out/listmonk /opt/listmonk-bin
COPY config.toml /etc/listmonk/config.toml
COPY entrypoint.sh start.sh restart.sh /arena/
RUN chmod -R a+rX /opt/challenge_src/listmonk \
 && chmod 0755 /opt/listmonk-bin /arena/entrypoint.sh /arena/start.sh /arena/restart.sh \
 && chmod 0644 /etc/listmonk/config.toml \
 && chmod 0700 /srv/listmonk/private

ENV PATH="/usr/local/go/bin:${PATH}" GOPATH=/go
EXPOSE 9000 22
ENTRYPOINT ["/arena/entrypoint.sh"]
