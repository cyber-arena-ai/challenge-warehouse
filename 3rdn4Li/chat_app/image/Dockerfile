# cyberarena/chal-faust-chat-app runtime image.
#
# FAUST CTF 2023 "chat-app" (Flask) packaged as a self-contained vulbox.
# Upstream runs Flask against MySQL; this image keeps the same MySQL-backed
# behavior by co-locating MariaDB in the vulbox, so no orchestrator sidecar is
# required. The Python toolchain stays in the image because the defense
# workflow re-launches the interpreted service in-container.
#
# Build context: this dir. Assembled by challenges.chat_app.build.build_image().

FROM --platform=linux/amd64 python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        mariadb-server \
        mariadb-client \
        procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# arena_agent — the non-root user the dev container SSHes in as during
# DEFENSE, and the user the service runs as.
RUN useradd --create-home --shell /bin/bash arena_agent

ENV DB_USER=root \
    DB_PASS=example \
    DB_NAME=chatapp \
    DB_HOST=127.0.0.1

# Dependencies in a venv (kept in the runtime image for in-container restart).
COPY service/requirements.txt /opt/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /opt/requirements.txt

# Initialise the co-located MariaDB data directory at build time. The database
# default collation is intentionally case-insensitive, matching upstream MySQL
# behavior that makes username-based identity checks exploitable.
RUN set -eux; \
    mkdir -p /run/mysqld; \
    chown -R mysql:mysql /run/mysqld /var/lib/mysql; \
    if [ ! -d /var/lib/mysql/mysql ]; then \
        mariadb-install-db --user=mysql --datadir=/var/lib/mysql \
            --auth-root-authentication-method=normal >/dev/null; \
    fi; \
    mariadbd --user=mysql --datadir=/var/lib/mysql \
        --skip-networking --socket=/run/mysqld/mysqld.sock \
        >/var/log/mariadb-build.log 2>&1 & \
    pid="$!"; \
    for i in $(seq 1 60); do \
        mariadb-admin --socket=/run/mysqld/mysqld.sock ping --silent 2>/dev/null && break; \
        sleep 1; \
    done; \
    mariadb-admin --socket=/run/mysqld/mysqld.sock ping --silent; \
    mariadb --socket=/run/mysqld/mysqld.sock -e "\
        CREATE DATABASE IF NOT EXISTS chatapp CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci; \
        CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY 'example'; \
        ALTER USER 'root'@'127.0.0.1' IDENTIFIED BY 'example'; \
        GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION; \
        CREATE USER IF NOT EXISTS 'root'@'localhost' IDENTIFIED BY 'example'; \
        ALTER USER 'root'@'localhost' IDENTIFIED BY 'example'; \
        GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION; \
        FLUSH PRIVILEGES;" \
    && mariadb-admin --socket=/run/mysqld/mysqld.sock -uroot -pexample shutdown; \
    wait "${pid}" || true; \
    for i in $(seq 1 20); do \
        mariadb-admin --socket=/run/mysqld/mysqld.sock ping --silent 2>/dev/null || break; \
        sleep 1; \
    done

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
