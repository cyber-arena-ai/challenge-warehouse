# cyberarena/chal-faust-treasury runtime image.
#
# FAUST CTF 2020 "treasury" (C binary, menu over a socket) packaged as a
# self-contained vulbox. The generic inetd wrapper replaces systemd socket
# activation; gcc stays in the image because the defense flow rebuilds the
# binary. Build context: this dir.

FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev make coreutils openssh-server procps python3 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent

# Bake source twice: read-only template (with pre-built binary) + writable copy.
COPY service/ /opt/challenge_src/treasury/app/
RUN cd /opt/challenge_src/treasury/app && make && chmod -R 555 /opt/challenge_src

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

EXPOSE 6789 22
CMD ["/arena/entrypoint.sh"]
