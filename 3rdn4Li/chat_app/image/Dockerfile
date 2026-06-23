# cyberarena/chal-faust-chat-app runtime image.
#
# FAUST CTF 2023 "chat-app" (Flask) packaged as a self-contained vulbox:
# the upstream external-MySQL dependency is replaced with in-image SQLite
# (see service/main.py), so nothing is fetched after build. The Python
# toolchain stays in the image because the defense workflow re-launches
# the (interpreted) service in-container.
#
# Build context: this dir. Assembled by challenges.chat_app.build.build_image().

FROM --platform=linux/amd64 python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# arena_agent — the non-root user the dev container SSHes in as during
# DEFENSE, and the user the service runs as (so its edits + the sqlite
# DB are writable without privilege).
RUN useradd --create-home --shell /bin/bash arena_agent

# Dependencies in a venv (kept in the runtime image for in-container restart).
COPY service/requirements.txt /opt/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /opt/requirements.txt

# Bake source twice:
#   /opt/challenge_src/chat-app/app/ — read-only template (root-owned 555)
#   /srv/challenge/chat-app/app/     — entrypoint cp -r's it per-container,
#                                      chowned to arena_agent; agent edits this.
COPY service/ /opt/challenge_src/chat-app/app/
RUN chmod -R 555 /opt/challenge_src

# Framework scripts: root-owned 555. Agent can read+exec, not modify.
COPY restart.sh /arena/restart.sh
COPY checker.sh /arena/checker.sh
RUN chmod 555 /arena/restart.sh /arena/checker.sh \
    && chown root:root /arena/restart.sh /arena/checker.sh

# sshd: non-root only. Agent key provisioned at install time.
RUN mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 555 /arena/entrypoint.sh && chown root:root /arena/entrypoint.sh

EXPOSE 5000 22

CMD ["/arena/entrypoint.sh"]
