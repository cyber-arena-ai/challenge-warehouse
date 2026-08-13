# cyberarena/chal-listmonk runtime image.
#
# listmonk (self-hosted newsletter/mailing-list manager, Go + PostgreSQL) pinned
# at upstream commit 171a597ff2f20e29dad9894418a4934f9ed30a58, collapsed into a
# single container: a co-resident PostgreSQL + the listmonk backend + sshd +
# arena_agent for the DEFENSE workflow. The framework deploys exactly one
# VulboxImage per team, so the usual app+db split is merged here.
#
# Only the Go backend is built (`go build`); the Vue admin SPA is NOT built.
# An un-stuffed listmonk binary loads its assets (queries/, schema.sql,
# static/, i18n/, config.toml.sample, frontend/dist) from the local filesystem
# at runtime (cmd/init.go: stuffbin.UnStuff fails -> NewLocalFS). The whole
# challenge is driven over the HTTP `/api/*` interface, which needs no SPA; a
# stub frontend/dist/index.html is baked so the asset loader is satisfied.
#
# Build context: this dir (jtu22/listmonk/image/).

FROM --platform=linux/amd64 golang:1.26.1-bookworm@sha256:ab3d6955bbc813a0f3fdf220c1d817dd89c0b3f283777db8ece4a32fe7858edd AS build

ARG LISTMONK_COMMIT=171a597ff2f20e29dad9894418a4934f9ed30a58
ENV DEBIAN_FRONTEND=noninteractive

# ── Fetch the exact upstream source and build the backend only ────────────────
WORKDIR /opt/challenge_src/listmonk
RUN git init -q \
    && git remote add origin https://github.com/knadh/listmonk.git \
    && git fetch --depth 1 origin "${LISTMONK_COMMIT}" \
    && git checkout -q --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${LISTMONK_COMMIT}" \
    # Assert the vulnerable export path is present exactly as expected: the
    # bulk CSV export core func must NOT validate query tables (unlike the
    # regular query path, which does). Fail the build loudly if upstream drift
    # changes this shape.
    && grep -qF 'func (c *Core) ExportSubscribers(' internal/core/subscribers.go \
    && grep -qF 'validateQueryTables(c.db, stmt, allowedSubQueryTables)' internal/core/subscribers.go \
    && awk '/func \(c \*Core\) ExportSubscribers\(/{e=1} /^}/{if(e)exit} e && /validateQueryTables/{print "UNEXPECTED: export validates tables"; exit 3}' internal/core/subscribers.go \
    && go mod download \
    && go build -buildvcs=false -o /opt/listmonk-bin ./cmd \
    && mkdir -p frontend/dist \
    && printf '<!doctype html><title>listmonk</title>listmonk admin API\n' > frontend/dist/index.html

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM --platform=linux/amd64 golang:1.26.1-bookworm@sha256:ab3d6955bbc813a0f3fdf220c1d817dd89c0b3f283777db8ece4a32fe7858edd

ENV DEBIAN_FRONTEND=noninteractive
ARG LISTMONK_COMMIT=171a597ff2f20e29dad9894418a4934f9ed30a58

# PostgreSQL both executes the injected export expression AND enforces the
# function revocations that keep the scored vulnerability the only way in
# (image/harden.sql), so its exact build is part of the challenge's semantics,
# not incidental tooling. Pin it twice over: apt is repointed at a fixed
# snapshot.debian.org timestamp (so a rebuild resolves the same archive whatever
# the date), and the package version is named explicitly (so a rebuild that
# somehow resolves anything else fails loudly instead of drifting). The stock
# deb822 source is removed, not merely supplemented -- leaving it in place lets
# apt satisfy the request from the live archive and silently defeats the pin.
ARG DEBIAN_SNAPSHOT=20260715T000000Z
ARG PG_PKG_VERSION=15.18-0+deb12u1
RUN rm -f /etc/apt/sources.list.d/* \
    && printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s bookworm main\ndeb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/%s bookworm-security main\n' \
        "${DEBIAN_SNAPSHOT}" "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=3 update \
    && apt-get install -y --no-install-recommends \
        "postgresql-15=${PG_PKG_VERSION}" "postgresql-client-15=${PG_PKG_VERSION}" \
        openssh-server \
        git ca-certificates procps curl python3 \
    && apt-cache policy postgresql-15 | grep -q snapshot.debian.org \
    && rm -rf /var/lib/apt/lists/*

# arena_agent (defender's non-root SSH login; key provisioned at deploy).
RUN useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /arena /etc/listmonk \
        /srv/challenge /srv/listmonk \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

# Pristine upstream source (read-only master copy) + the pre-built binary +
# Go module cache, so the defender's later `go build` rebuild is fully offline.
COPY --from=build /opt/challenge_src/listmonk /opt/challenge_src/listmonk
COPY --from=build /opt/listmonk-bin /opt/listmonk-bin
COPY --from=build /go/pkg/mod /go/pkg/mod
RUN chmod -R a+rX /opt/challenge_src/listmonk

COPY config.toml /etc/listmonk/config.toml
COPY entrypoint.sh start.sh restart.sh checker.py seed.sql harden.sql flag_store.py /arena/
RUN chmod 0755 /arena/entrypoint.sh /arena/start.sh /arena/restart.sh /arena/checker.py \
    && chmod 0600 /arena/seed.sql /arena/harden.sql \
    && chmod 0700 /arena/flag_store.py \
    && chown -R root:root /arena \
    && chmod 0644 /etc/listmonk/config.toml

EXPOSE 9000 22

ENTRYPOINT ["/arena/entrypoint.sh"]
