# cyberarena/chal-blockrope runtime image.
#
# saarCTF 2025 "blockrope" (Python "blockchain bank", menu over a socket)
# packaged as a self-contained vulbox. The generic inetd wrapper replaces the
# upstream socat unit; there's no compile step (interpreted Python), so the
# defense "rebuild" is a py_compile syntax gate in restart.sh. Build context:
# this dir.

FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 ncurses-bin coreutils procps openssh-server \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent

# Bake source twice: read-only template + writable copy created at boot.
COPY service/ /opt/challenge_src/blockrope/app/
RUN python3 -m py_compile /opt/challenge_src/blockrope/app/main.py \
                          /opt/challenge_src/blockrope/app/util.py \
                          /opt/challenge_src/blockrope/app/cleaner.py \
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

EXPOSE 1337 22
CMD ["/arena/entrypoint.sh"]
