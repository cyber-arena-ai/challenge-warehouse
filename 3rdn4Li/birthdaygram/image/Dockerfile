# cyberarena/chal-faust-birthdaygram runtime image.
#
# FAUST CTF 2025 "birthdaygram" (Flask + Pillow, JWT) packaged as a
# self-contained vulbox: external Postgres -> in-image SQLite (service/app.py),
# nothing fetched after build, Python toolchain kept for in-container restart.
#
# Build context: this dir. Assembled by challenges.birthdaygram.build.build_image().

FROM --platform=linux/amd64 python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent

COPY service/requirements.txt /opt/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r /opt/requirements.txt gunicorn

# Bake source twice: read-only template + per-container writable copy.
COPY service/ /opt/challenge_src/birthdaygram/app/
RUN chmod -R 555 /opt/challenge_src

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

EXPOSE 3000 22

CMD ["/arena/entrypoint.sh"]
