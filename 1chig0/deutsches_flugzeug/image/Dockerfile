# cyberarena/chal-deutsches-flugzeug runtime image.
#
# saarCTF 2024 "deutsches-flugzeug" (German Flask flight-booking webapp) packaged
# as a self-contained vulbox. The app is served by gunicorn on HTTP 5000 with a
# co-located sqlite3 database (upstream used sqlite3, baked into the image and
# initialised at build). The whole thing starts offline — nothing is fetched at
# run time.
#
# THE VULN is a wrong-library-version bug (CVE-2022-39227): the service venv pins
# the OUTDATED `python-jwt==3.0`, whose verify_jwt accepts a re-wrapped token that
# reuses a valid signature with attacker-chosen claims. The DEFENSE is to upgrade
# the library to a patched release (>= 3.3.4); the patched wheels are pre-baked
# under /opt/wheels so the upgrade works fully offline. Build context: this dir.
#
# The service venv is built directly at its FINAL runtime path
# (/srv/challenge/deutsches-flugzeug/app/venv) so the defender's offline
# `pip install` rewrites in place (a venv has absolute paths baked into pip's
# shebang + sys.prefix; copying it elsewhere would break uninstall). The boot
# entrypoint copies only the app *source* into place and leaves the venv put.

FROM --platform=linux/amd64 python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server procps ghostscript ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent

ENV APP_DIR=/srv/challenge/deutsches-flugzeug/app
ENV VENV=/srv/challenge/deutsches-flugzeug/app/venv

# --- Service source + virtualenv at their FINAL runtime paths ----------------
COPY service/ ${APP_DIR}/
# python-jwt==3.0 is the VULNERABLE pin (CVE-2022-39227); the rest is the
# upstream dependency set.
RUN python3 -m venv ${VENV} \
    && ${VENV}/bin/pip install --no-cache-dir --upgrade pip \
    && ${VENV}/bin/pip install --no-cache-dir \
        flask==3.0.3 \
        'python-jwt==3.0' \
        jwcrypto==1.5.6 \
        treepoem==3.24.0 \
        Pillow==10.4.0 \
        gunicorn==22.0.0

# --- Patched wheels for the offline defense upgrade -------------------------
# The defender runs:
#   venv/bin/pip install --no-index --find-links /opt/wheels 'python-jwt==3.3.4'
RUN ${VENV}/bin/pip download --no-cache-dir -d /opt/wheels 'python-jwt==3.3.4' \
    && chmod -R a+rX /opt/wheels

# Initialise the sqlite DB + schema at build (offline).
RUN mkdir -p ${APP_DIR}/data \
    && ${VENV}/bin/python -c \
        "import sqlite3; c=sqlite3.connect('${APP_DIR}/data/datenbank.sqlite3'); \
         c.executescript(open('${APP_DIR}/dieAnwendung/schema.sql').read()); c.close()"

# A pristine read-only copy of the app SOURCE (no venv) used to repopulate the
# writable tree at boot. The venv stays at ${VENV} untouched between boots.
RUN mkdir -p /opt/challenge_src/deutsches-flugzeug \
    && cp -a ${APP_DIR} /opt/challenge_src/deutsches-flugzeug/app \
    && rm -rf /opt/challenge_src/deutsches-flugzeug/app/venv \
    && chmod -R 555 /opt/challenge_src

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

EXPOSE 5000 22
CMD ["/arena/entrypoint.sh"]
