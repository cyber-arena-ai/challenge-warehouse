# cyberarena/chal-certified-transparency runtime image.
#
# saarCTF 2024 "Certified Transparency" (a Go certificate-transparency-style
# log) packaged as a self-contained vulbox. Two HTTP daemons:
#   * log     on :3000  (append/get entries, sign-entry, get-sth/proof)
#   * monitor on :3001  (claim-private / claim-public / websocket watch)
# Storage is an EMBEDDED BadgerDB under <app>/data/ (NO postgres / no external
# DB — the upstream install.sh's postgres lines are commented-out examples).
#
# The Go toolchain + a fully-populated module/build cache stay in the image so
# the defense flow can `go build` again completely offline (SOP §4). The initial
# binaries are compiled at image-build; the GOPATH module cache + GOCACHE are
# baked so the rebuild never touches the network. Build context: this dir.

FROM --platform=linux/amd64 golang:1.22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server procps python3 ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent

# Bake source as a read-only template; a writable copy is made at boot. The
# `go build` here also fully populates GOPATH ($GOPATH/pkg/mod) + GOCACHE so the
# offline defense rebuild has every dependency + compiled object locally.
ENV GOPATH=/go GOCACHE=/root/.cache/go-build GOFLAGS=-mod=mod
COPY service/ /opt/challenge_src/certified-transparency/app/
RUN cd /opt/challenge_src/certified-transparency/app \
    && go mod download \
    && go build -o bin/log ./cmd/log \
    && go build -o bin/monitor ./cmd/monitor \
    && chmod -R a+rX /go /root/.cache/go-build \
    && chmod -R 555 /opt/challenge_src

COPY restart.sh /arena/restart.sh
COPY checker.sh /arena/checker.sh
RUN chmod 555 /arena/restart.sh /arena/checker.sh \
    && chown root:root /arena/restart.sh /arena/checker.sh

RUN mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 555 /arena/entrypoint.sh && chown root:root /arena/entrypoint.sh

EXPOSE 3000 3001 22
CMD ["/arena/entrypoint.sh"]
