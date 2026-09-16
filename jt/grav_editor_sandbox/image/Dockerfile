# cyberarena/chal-grav-editor-sandbox — Grav CMS editor sandbox.
#
# Pinned upstream: the OFFICIAL grav-admin 2.0.0-beta.1 release bundle
#   https://github.com/getgrav/grav/releases/download/2.0.0-beta.1/grav-admin-v2.0.0-beta.1.zip
#   archive SHA-256 4489f70b6e2b680306b19ed0aee3cccc26ff7454097d638bed43d03854d8ff31
#   core tag/commit 26a2d519c59c620e2b0a54d0baf33889d7d5db0a
# The archive is fetched and hash-verified at BUILD time; nothing is fetched at
# run time. The bundle ships unmodified — the served tree IS the editable tree.
#
# The service runs as the dedicated unprivileged account `grav` (UID/GID 1001).
# The defender edits /srv/challenge/grav over ssh as arena_agent (a member of the
# grav group) and calls restart_service, which runs /arena/restart.sh.

# ── stage 1: the command objective's setuid helper ──────────────────────────
FROM --platform=linux/amd64 debian:bookworm-slim AS helper
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY catflag.c /tmp/catflag.c
RUN gcc -O2 -Wall -Wextra -static -o /tmp/catflag /tmp/catflag.c && strip /tmp/catflag

# ── stage 2: the Grav runtime ───────────────────────────────────────────────
FROM --platform=linux/amd64 php:8.3-cli-bookworm

ARG GRAV_URL=https://github.com/getgrav/grav/releases/download/2.0.0-beta.1/grav-admin-v2.0.0-beta.1.zip
ARG GRAV_SHA256=4489f70b6e2b680306b19ed0aee3cccc26ff7454097d638bed43d03854d8ff31

# Grav's own PHP extension requirements (the set the feasibility runtime used),
# plus the arena's platform requirements: sshd for the defender, procps/curl for
# the restart and facility paths, unzip for the release bundle.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libcurl4-openssl-dev \
        libfreetype6-dev \
        libicu-dev \
        libjpeg62-turbo-dev \
        libonig-dev \
        libpng-dev \
        libxml2-dev \
        libzip-dev \
        openssh-server \
        procps \
        unzip \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j2 curl dom gd intl mbstring zip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged service account; arena_agent shares its group so the
# defender can edit the tree the service reads.
RUN groupadd --gid 1001 grav \
    && useradd --uid 1001 --gid 1001 --home-dir /home/grav --create-home \
       --shell /usr/sbin/nologin grav \
    && useradd --create-home --shell /bin/bash --groups grav arena_agent

# The official bundle, hash-verified, extracted as the complete editable source.
RUN set -eux; \
    curl -fsSL -o /tmp/grav-admin.zip "$GRAV_URL"; \
    echo "${GRAV_SHA256}  /tmp/grav-admin.zip" | sha256sum -c -; \
    mkdir -p /srv/challenge; \
    unzip -q /tmp/grav-admin.zip -d /tmp/grav-extract; \
    mv /tmp/grav-extract/grav-admin /srv/challenge/grav; \
    rm -rf /tmp/grav-admin.zip /tmp/grav-extract; \
    chown -R arena_agent:grav /srv/challenge/grav; \
    chmod -R ug+rwX /srv/challenge/grav

# The command objective: root-only backing store + the fixed setuid helper.
COPY --from=helper /tmp/catflag /usr/local/bin/catflag
RUN mkdir -p /var/lib/arena/command /arena/secrets /arena/state \
    && chown root:root /var/lib/arena/command /arena/secrets /arena/state \
    && chmod 0700 /var/lib/arena/command /arena/secrets /arena/state \
    && chown root:root /usr/local/bin/catflag \
    && chmod 4755 /usr/local/bin/catflag

COPY entrypoint.sh /arena/entrypoint.sh
COPY restart.sh /arena/restart.sh
COPY setup.php /arena/setup.php
RUN chown root:root /arena/entrypoint.sh /arena/restart.sh /arena/setup.php \
    && chmod 555 /arena/entrypoint.sh /arena/restart.sh /arena/setup.php \
    && touch /var/log/grav-svc.log && chown grav:grav /var/log/grav-svc.log \
    && touch /run/grav-svc.pgid && chown grav:grav /run/grav-svc.pgid

# sshd: default-deny root; the framework flips it on per-deploy for the defender.
RUN mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 8080 22
ENTRYPOINT []
CMD ["/arena/entrypoint.sh"]
