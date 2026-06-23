# cyberarena/chal-btx runtime image.
#
# saarCTF 2024 "btx" (Bildschirmtext / videotex, a Python CEPT terminal service
# speaking a binary/escape menu protocol over TCP 1983) packaged as a
# self-contained vulbox. The generic inetd wrapper replaces the upstream
# `socat ... EXEC:'python3 -u neu-ulm.py'` unit (one process per connection).
#
# The service is pure interpreted Python with a flat-file backend (JSON files
# under users/ secrets/ blogs/ stats/) — there is NO database. (The upstream
# install.sh only contained commented-out PostgreSQL *examples*; the btx app
# itself never imports a DB driver.) So the defense "rebuild" is a py_compile
# syntax gate in restart.sh, and nothing has to be started before the app.
#
# Build context: this dir.

FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 procps coreutils openssh-server \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent

# Bake source twice: read-only template + a writable copy created at boot.
# The service's runtime cwd is .../server/ ; it reads ../data and writes to
# ../{users,secrets,blogs,stats}. Those state dirs are seeded at boot from the
# template's `state/` (which carries the guest account 0-1).
COPY service/ /opt/challenge_src/btx/app/
RUN python3 -m py_compile \
        /opt/challenge_src/btx/app/server/neu-ulm.py \
        /opt/challenge_src/btx/app/server/blog.py \
        /opt/challenge_src/btx/app/server/user.py \
        /opt/challenge_src/btx/app/server/login.py \
        /opt/challenge_src/btx/app/server/editor.py \
        /opt/challenge_src/btx/app/server/util.py \
        /opt/challenge_src/btx/app/server/cept.py \
    && chmod -R 555 /opt/challenge_src

COPY inetd.py /arena/inetd.py
COPY restart.sh /arena/restart.sh
COPY checker.sh /arena/checker.sh
RUN chmod 555 /arena/inetd.py /arena/restart.sh /arena/checker.sh \
    && chown root:root /arena/inetd.py /arena/restart.sh /arena/checker.sh

RUN mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 555 /arena/entrypoint.sh && chown root:root /arena/entrypoint.sh

EXPOSE 1983 22
CMD ["/arena/entrypoint.sh"]
