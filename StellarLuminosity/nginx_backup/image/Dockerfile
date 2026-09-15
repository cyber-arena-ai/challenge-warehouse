FROM --platform=linux/amd64 node:24-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e AS frontend

COPY source-primary.tar.gz /tmp/source.tar.gz
RUN echo "a31f1da371af9e0aa5cd7cd4837da5f6e30a97f35e7baff8c800d3ea4d627d5b  /tmp/source.tar.gz" | sha256sum -c - \
    && mkdir /src \
    && tar -xzf /tmp/source.tar.gz --strip-components=1 -C /src \
    && rm /tmp/source.tar.gz
WORKDIR /src
RUN corepack enable \
    && corepack prepare 'pnpm@10.28.2+sha512.41872f037ad22f7348e3b1debbaf7e867cfd448f2726d9cf74c08f19507c31d2c8e7a11525b983febc2df640b5438dee6023ebb1f84ed43cc2d654d2bc326264' --activate \
    && test "$(pnpm --version)" = "10.28.2" \
    && pnpm install --frozen-lockfile \
    && pnpm build

FROM --platform=linux/amd64 golang:1.25.6-bookworm@sha256:f4490d7b261d73af4543c46ac6597d7d101b6e1755bcdd8c5159fda7046b6b3e

ENV DEBIAN_FRONTEND=noninteractive \
    GOTOOLCHAIN=local \
    NGINX_UI_WORKING_DIR=/var/run/

RUN sed -i \
        -e 's|URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20260824T000000Z|' \
        -e 's|URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/20260824T000000Z|' \
        -e '/Signed-By:/a Check-Valid-Until: no' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419~deb12u1 \
        curl=7.88.1-10+deb12u15 \
        nginx=1.22.1-9+deb12u9 \
        openssh-server=1:9.2p1-2+deb12u10 \
        openssl=3.0.20-1~deb12u2 \
        procps=2:4.0.2-3 \
        python3=3.11.2-1+b1 \
        util-linux=2.38.1-5+deb12u3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY --from=frontend /src /opt/nginx-ui-source
COPY --from=frontend /usr/local/bin/node /usr/local/bin/node
COPY --from=frontend /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=frontend /root/.cache/node/corepack /root/.cache/node/corepack
COPY ordered_backup.go patch_source.py /tmp/arena-source/
RUN ln -s ../lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack \
    && ln -s ../lib/node_modules/corepack/dist/pnpm.js /usr/local/bin/pnpm \
    && ln -s ../lib/node_modules/corepack/dist/pnpx.js /usr/local/bin/pnpx \
    && python3 /tmp/arena-source/patch_source.py /opt/nginx-ui-source \
    && install -m 0444 /tmp/arena-source/ordered_backup.go \
        /opt/nginx-ui-source/internal/backup/arena_ordered_backup.go \
    && rm -rf /tmp/arena-source

WORKDIR /opt/nginx-ui-source
RUN go mod download \
    && CGO_ENABLED=1 go build -buildvcs=false -trimpath -tags=jsoniter \
        -ldflags "-X 'github.com/0xJacky/Nginx-UI/internal/version.Version=2.3.2' -X 'github.com/0xJacky/Nginx-UI/internal/version.Hash=2ae32f3be5fccaca013e14fef6e497acaaae21ba' -X 'github.com/0xJacky/Nginx-UI/settings.buildTime=1'" \
        -o /usr/local/bin/nginx-ui main.go

COPY entrypoint.sh restart.sh provision.py /arena/
RUN chmod 0555 /arena/entrypoint.sh /arena/restart.sh /arena/provision.py

EXPOSE 22 9000
ENTRYPOINT ["/arena/entrypoint.sh"]
