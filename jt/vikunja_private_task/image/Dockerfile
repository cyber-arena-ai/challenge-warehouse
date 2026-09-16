FROM --platform=linux/amd64 golang@sha256:f6751d823c26342f9506c03797d2527668d095b0a15f1862cddb4d927a7a4ced AS go

FROM --platform=linux/amd64 node@sha256:931d7d57f8c1fd0e2179dbff7cc7da4c9dd100998bc2b32afc85142d8efbc213

ARG SOURCE_SHA256=aee3d521351a5a479df567ab35688a67650ddd26588f3540198a43ad75c13d1f

ENV PATH=/usr/local/go/bin:/opt/pnpm/bin:$PATH \
    PNPM_HOME=/opt/pnpm/bin \
    GOMODCACHE=/opt/go/pkg/mod \
    GOCACHE=/opt/go/cache \
    PUPPETEER_SKIP_DOWNLOAD=true

COPY --from=go /usr/local/go /usr/local/go

RUN apk add --no-cache \
        bash=5.3.3-r1 \
        build-base=0.5-r3 \
        ca-certificates=20260611-r0 \
        openssh-server=10.2_p1-r0 \
        procps-ng=4.0.5-r0 \
        su-exec=0.3-r0 \
    && npm install --global pnpm@10.28.1 \
    && deluser node \
    && addgroup -S -g 1000 vikunja \
    && adduser -S -D -H -u 1000 -G vikunja vikunja \
    && adduser -D -u 1001 -s /bin/bash arena_agent \
    && addgroup arena_agent vikunja

COPY vikunja-b365be1881641dd2791d3dff4c26ad941c13cef6.tar.gz /tmp/vikunja.tar.gz
RUN mkdir -p /srv/challenge/vikunja /opt/pnpm-store /opt/go/pkg/mod /opt/go/cache \
    && echo "$SOURCE_SHA256  /tmp/vikunja.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/vikunja.tar.gz --strip-components=1 -C /srv/challenge/vikunja \
    && rm /tmp/vikunja.tar.gz \
    && cd /srv/challenge/vikunja/frontend \
    && pnpm config set store-dir /opt/pnpm-store \
    && pnpm install --frozen-lockfile \
    && pnpm run build \
    && cd /srv/challenge/vikunja \
    && go mod download \
    && CGO_ENABLED=1 go build -buildvcs=false -tags osusergo \
        -ldflags '-s -w -X code.vikunja.io/api/pkg/version.Version=v2.2.0 -X main.Tags=osusergo' \
        -o /arena/vikunja . \
    && chown -R arena_agent:vikunja /srv/challenge/vikunja \
    && chmod -R ug+rwX /srv/challenge/vikunja

COPY catflag.c /tmp/catflag.c
RUN gcc -Os -static -Wall -Wextra -o /usr/local/bin/catflag /tmp/catflag.c \
    && strip /usr/local/bin/catflag \
    && chown root:root /usr/local/bin/catflag \
    && chmod 4755 /usr/local/bin/catflag \
    && rm /tmp/catflag.c

COPY entrypoint.sh restart.sh facility.sh facility-http.js /arena/
RUN mkdir -p /arena/data/files /arena/secrets /arena/state /var/lib/arena/command \
        /var/lib/vikunja-plants \
        /run/sshd /home/arena_agent/.ssh \
    && chown -R vikunja:vikunja /arena/data \
    && chmod 0700 /arena/secrets /arena/state /var/lib/arena/command \
    && chown root:root /var/lib/vikunja-plants \
    && chmod 0700 /var/lib/vikunja-plants \
    && printf '%s\n' vikunja-plants-v1:virgin \
        > /var/lib/.vikunja-plants.initialized \
    && printf '%s\n' vikunja-baseline-v1:virgin \
        > /var/lib/.vikunja-baseline.initialized \
    && chown root:root /var/lib/.vikunja-plants.initialized \
        /var/lib/.vikunja-baseline.initialized \
    && chmod 0400 /var/lib/.vikunja-plants.initialized \
        /var/lib/.vikunja-baseline.initialized \
    && chown root:root /arena/entrypoint.sh /arena/restart.sh \
        /arena/facility.sh /arena/facility-http.js \
    && chmod 0555 /arena/entrypoint.sh /arena/restart.sh \
        /arena/facility.sh /arena/facility-http.js \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 3456 22
ENTRYPOINT []
CMD ["/arena/entrypoint.sh"]
