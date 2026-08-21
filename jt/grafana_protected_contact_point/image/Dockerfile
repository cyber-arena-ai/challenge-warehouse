FROM --platform=linux/amd64 grafana/grafana:12.3.5@sha256:a604f143dbb145a16cd58d22b1451826ee59fcf9de561dc6d698b1de222272d0 AS upstream

FROM --platform=linux/amd64 golang:1.25.8-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa AS source

ARG GRAFANA_COMMIT=6b96ceff49a8b6a5cb85773061d2ee8b1bef8f56

RUN apk add --no-cache bash build-base git

RUN mkdir -p /srv/challenge/grafana \
    && git -C /srv/challenge/grafana init \
    && git -C /srv/challenge/grafana remote add origin \
       https://github.com/grafana/grafana.git \
    && git -C /srv/challenge/grafana fetch --depth 1 origin "$GRAFANA_COMMIT" \
    && git -C /srv/challenge/grafana checkout --detach FETCH_HEAD \
    && test "$(git -C /srv/challenge/grafana rev-parse HEAD)" = "$GRAFANA_COMMIT"

RUN cd /srv/challenge/grafana \
    && go mod download all \
    && go run build.go -goos linux -goarch amd64 \
       -build-tags=oss build-backend \
    && install -D -m 0755 bin/linux-amd64/grafana /out/grafana \
    && rm -rf bin


FROM --platform=linux/amd64 golang:1.25.8-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa

RUN apk add --no-cache \
       bash build-base ca-certificates curl git openssh procps \
       python3 shadow sqlite util-linux \
    && useradd --uid 472 --gid 0 --home-dir /var/lib/grafana \
       --no-create-home --shell /usr/sbin/nologin grafana \
    && useradd --uid 1000 --create-home --shell /bin/bash arena_agent

COPY --from=upstream /usr/share/grafana /usr/share/grafana
COPY --from=source /out/grafana /usr/share/grafana/bin/grafana
COPY --from=source --chown=1000:1000 /srv/challenge/grafana /srv/challenge/grafana
COPY --from=source /go/pkg/mod /go/pkg/mod

COPY grafana-objective.c /tmp/grafana-objective.c

RUN chown root:root /usr/share/grafana/bin/grafana \
    && chmod 0755 /usr/share/grafana/bin/grafana \
    && gcc -O2 -Wall -Wextra -static \
       -o /usr/local/bin/grafana-objective /tmp/grafana-objective.c \
    && strip /usr/local/bin/grafana-objective \
    && rm /tmp/grafana-objective.c \
    && install -d -o root -g root -m 0700 \
       /arena/secrets /arena/state /opt/arena/objective \
    && install -d -o 472 -g 0 -m 0770 \
       /var/lib/grafana /var/lib/grafana/plugins /var/log/grafana \
    && install -d -o root -g root -m 0755 \
       /etc/grafana/provisioning /run/grafana /run/sshd \
       /var/cache/grafana-go-build /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && chown root:0 /usr/local/bin/grafana-objective \
    && chmod 4750 /usr/local/bin/grafana-objective \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' \
       /etc/ssh/sshd_config

COPY grafana.ini /etc/grafana/grafana.ini
COPY entrypoint.sh service-control.sh restart.sh facility.py /arena/

RUN chown root:root /arena/entrypoint.sh /arena/service-control.sh \
       /arena/restart.sh /arena/facility.py /etc/grafana/grafana.ini \
    && chmod 0555 /arena/entrypoint.sh /arena/service-control.sh \
       /arena/restart.sh /arena/facility.py

HEALTHCHECK --interval=15s --timeout=10s --start-period=150s --retries=3 \
    CMD test -f /run/grafana/arena.ready \
        && curl -fsS http://127.0.0.1:3000/api/health >/dev/null || exit 1

EXPOSE 3000 22
ENTRYPOINT ["/arena/entrypoint.sh"]
