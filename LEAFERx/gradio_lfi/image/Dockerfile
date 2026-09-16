FROM --platform=linux/amd64 python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MPLCONFIGDIR=/tmp/matplotlib \
    GRADIO_ANALYTICS_ENABLED=False

RUN sed -i \
        '/^URIs: http:\/\/deb.debian.org\/debian$/c\URIs: https://snapshot.debian.org/archive/debian/20260824T000000Z' \
        /etc/apt/sources.list.d/debian.sources \
    && sed -i \
        '/^URIs: http:\/\/deb.debian.org\/debian-security$/c\URIs: https://snapshot.debian.org/archive/debian-security/20260824T000000Z' \
        /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\n' \
        > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419 \
        openssh-server=1:10.0p1-7+deb13u4 \
        procps=2:4.0.4-9 \
        util-linux=2.41.5-0+deb13u1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /opt/gradio-build/requirements.lock
RUN python -m pip install --no-deps --requirement /opt/gradio-build/requirements.lock

# Wheel assets come from the contemporaneous 4.12.0 distribution; the complete
# Python backend is replaced by the exact accepted vulnerable Git revision.
COPY source/gradio-53b95f8683bf80579fc5c242dfdfb74143e0c235.tar.gz /tmp/gradio-source.tar.gz
RUN tar -xzf /tmp/gradio-source.tar.gz -C /usr/local/lib/python3.11/site-packages \
    && rm /tmp/gradio-source.tar.gz \
    && mkdir -p /opt/challenge-src \
    && cp -a /usr/local/lib/python3.11/site-packages/gradio /opt/challenge-src/gradio

COPY app.py /opt/challenge-src/app.py
COPY facility.py /arena/facility.py
COPY restart.sh /arena/restart.sh
COPY stop.sh /arena/stop.sh
COPY entrypoint.sh /arena/entrypoint.sh

RUN useradd --create-home --shell /bin/bash arena_agent \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
    && chmod 0555 /arena/facility.py /arena/restart.sh /arena/stop.sh /arena/entrypoint.sh \
    && chown root:root /arena/facility.py /arena/restart.sh /arena/stop.sh /arena/entrypoint.sh \
    && mkdir -p /srv/challenge \
    && cp -a /opt/challenge-src/gradio /srv/challenge/gradio \
    && cp -a /opt/challenge-src/app.py /srv/challenge/app.py \
    && chown -R arena_agent:arena_agent /srv/challenge \
    && chmod -R a+rX,u+w /srv/challenge \
    && chmod -R a-w /opt/challenge-src \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /tmp/gradio /tmp/matplotlib \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && chown -R appuser:appuser /tmp/gradio /tmp/matplotlib \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 7860 22
CMD ["/arena/entrypoint.sh"]
