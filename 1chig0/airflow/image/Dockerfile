# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2

ARG AIRFLOW_COMMIT=06b74e0c48d8fc5bfa6b99626370512fc4460c88
ARG AIRFLOW_ARCHIVE_SHA256=b21523568e101faf6d9c2c6ef7d24eb54d23628202e4bc290376e8a6672da70d
ARG DEBIAN_SNAPSHOT=20260803T000000Z

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AIRFLOW_HOME=/var/lib/airflow \
    AIRFLOW__CORE__AUTH_MANAGER=airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager \
    AIRFLOW__CORE__LOAD_EXAMPLES=False \
    AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=sqlite:////var/lib/airflow/airflow.db \
    AIRFLOW__API__WORKERS=1 \
    AIRFLOW__LOGGING__LOGGING_LEVEL=WARNING

RUN sed -i \
      -e "s|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|" \
      -e "s|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install --no-install-recommends -y \
        ca-certificates=20230311+deb12u1 \
        curl=7.88.1-10+deb12u15 \
        openssh-server=1:9.2p1-2+deb12u10 \
        procps=2:4.0.2-3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /tmp/airflow-requirements.lock
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
      --no-deps --only-binary=:all: --require-hashes \
      -r /tmp/airflow-requirements.lock

RUN curl -fL --retry 3 \
      -o /tmp/airflow-source.tar.gz \
      "https://github.com/apache/airflow/archive/${AIRFLOW_COMMIT}.tar.gz" \
    && echo "${AIRFLOW_ARCHIVE_SHA256}  /tmp/airflow-source.tar.gz" \
      | sha256sum -c - \
    && mkdir -p /opt/airflow-source \
    && tar -xzf /tmp/airflow-source.tar.gz --strip-components=1 \
      -C /opt/airflow-source \
    && rm /tmp/airflow-source.tar.gz \
    && python -m pip install --disable-pip-version-check --no-cache-dir \
      --no-index --no-deps --no-build-isolation \
      /opt/airflow-source/providers/fab

RUN useradd --uid 50000 --gid 0 --create-home --shell /bin/bash airflow \
    && useradd --create-home --shell /bin/bash --groups root arena_agent \
    && install -d -o root -g root -m 0755 /arena /run/sshd \
    && install -d -o airflow -g root -m 0770 /var/lib/airflow \
    && install -d -o arena_agent -g arena_agent -m 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY --chmod=0555 entrypoint.sh restart.sh start.sh facility.py identity.py /arena/

LABEL org.opencontainers.image.source="https://github.com/apache/airflow" \
      org.opencontainers.image.revision="${AIRFLOW_COMMIT}" \
      cyberarena.source.archive-sha256="${AIRFLOW_ARCHIVE_SHA256}" \
      cyberarena.build.debian-snapshot="${DEBIAN_SNAPSHOT}" \
      cyberarena.build.requirements-sha256="01d579171ed13dbc0e3b85fc13cdadc39527375257e133bc0622094e463507b4"

EXPOSE 8080 22
ENTRYPOINT ["/arena/entrypoint.sh"]
