FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN sed -i \
        's|URIs: http://deb.debian.org/debian-security|URIs: http://snapshot.debian.org/archive/debian-security/20260824T000000Z|; s|URIs: http://deb.debian.org/debian|URIs: http://snapshot.debian.org/archive/debian/20260824T000000Z|' \
        /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\n' \
        > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential=12.12 \
        ca-certificates=20250419 \
        openssh-server=1:10.0p1-7+deb13u4 \
        procps=2:4.0.4-9 \
        util-linux=2.41.5-0+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /tmp/requirements.lock
RUN python -m pip install \
        --disable-pip-version-check \
        --no-deps \
        --no-index \
        --require-hashes \
        -r /tmp/requirements.lock \
    && python -m pip check \
    && rm /tmp/requirements.lock

COPY source-primary.tar.gz /tmp/source-primary.tar.gz
RUN echo "f932991684ecb9d5e607634aacb234256e72006e812f12af147d5951c563de9d  /tmp/source-primary.tar.gz" \
        | sha256sum -c - \
    && mkdir -p /opt/marimo-source \
    && tar -xzf /tmp/source-primary.tar.gz -C /opt/marimo-source \
    && cp -a /usr/local/lib/python3.11/site-packages/marimo/_static /opt/marimo-source/marimo/_static \
    && rm /tmp/source-primary.tar.gz \
    && grep -qF '@router.websocket("/ws")' /opt/marimo-source/marimo/_server/api/endpoints/terminal.py \
    && ! grep -A12 -F '@router.websocket("/ws")' /opt/marimo-source/marimo/_server/api/endpoints/terminal.py \
        | grep -qF 'validate_auth(websocket)' \
    && chmod -R a-w /opt/marimo-source

RUN useradd --uid 1000 --create-home --shell /bin/bash marimo \
    && useradd --uid 1001 --create-home --shell /bin/bash arena_agent \
    && mkdir -p /arena /run/marimo /run/sshd /srv/challenge /srv/state \
    && chown marimo:marimo /run/marimo /srv/state \
    && chmod 0755 /srv/state \
    && chmod 0700 /home/arena_agent

COPY marimo-proof.c /tmp/marimo-proof.c
RUN cc -O2 -Wall -Wextra -Werror -o /usr/local/bin/marimo-proof /tmp/marimo-proof.c \
    && chown root:root /usr/local/bin/marimo-proof \
    && chmod 4555 /usr/local/bin/marimo-proof \
    && rm /tmp/marimo-proof.c

COPY notebook.py /opt/notebook.py
COPY entrypoint.sh facility.py restart.sh service-owner.sh sitecustomize.py stop.sh /arena/
RUN chmod 0555 /arena/entrypoint.sh /arena/facility.py /arena/restart.sh /arena/service-owner.sh /arena/sitecustomize.py /arena/stop.sh \
    && chmod 0444 /opt/notebook.py \
    && chown -R root:root /arena /opt/notebook.py \
    && ssh-keygen -A \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 2718 22
ENTRYPOINT ["/arena/entrypoint.sh"]
