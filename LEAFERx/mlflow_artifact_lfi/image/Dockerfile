# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN sed -i \
        -e 's|URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20260824T000000Z|' \
        -e 's|URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/20260824T000000Z|' \
        -e '/Signed-By:/a Check-Valid-Until: no' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419 \
        openssh-server=1:10.0p1-7+deb13u4 \
        procps=2:4.0.4-9 \
        util-linux=2.41.5-0+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent \
    && useradd --no-create-home --shell /usr/sbin/nologin mlflow

WORKDIR /opt/mlflow-source
COPY requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir setuptools==82.0.1 \
    && python -m pip install --no-cache-dir -r /tmp/requirements.lock

COPY source-primary.tar.gz /tmp/source-primary.tar.gz
RUN tar -xzf /tmp/source-primary.tar.gz -C /opt/mlflow-source \
    && python -m pip install --no-cache-dir --no-deps --no-build-isolation /opt/mlflow-source \
    && rm /tmp/source-primary.tar.gz

RUN install -d -m 0755 /srv/challenge /srv/mlflow/state \
    && install -d -m 0750 -o root -g mlflow /srv/mlflow/private \
    && chown -R mlflow:mlflow /srv/mlflow/state \
    && install -d -m 0700 /home/arena_agent/.ssh /run/sshd \
    && chown -R arena_agent:arena_agent /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY entrypoint.sh /arena/entrypoint.sh
COPY restart.sh /arena/restart.sh
RUN chmod 0555 /arena/entrypoint.sh /arena/restart.sh \
    && chown root:root /arena/entrypoint.sh /arena/restart.sh

EXPOSE 5000 22
ENTRYPOINT ["/arena/entrypoint.sh"]
