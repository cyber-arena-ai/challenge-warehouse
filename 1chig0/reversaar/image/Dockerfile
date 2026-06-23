# cyberarena/chal-reversaar runtime image.
#
# saarCTF 2024 "reversaar" (obfuscated C CGI reversing service) packaged as a
# self-contained vulbox. HTTP on port 7331, served by nginx -> spawn-fcgi ->
# fcgiwrap -> the plain-CGI binary `reversaar.cgi` (exactly the upstream stack).
#
# The /api/array endpoint loads a *separate* shared object (array.so) at runtime
# from an encrypted blob (.tmp.bin). The blob is produced by the upstream build
# codegen: compile array.so -> forge_crc32.py (CRC self-reference) -> rc4wrap.py
# (RC4 + random padding). reversaar.cgi statically embeds the rest.
#
# The C toolchain + the build codegen stay in the image so the defense flow can
# rebuild from source offline (SOP §4). The initial binary + .tmp.bin are built
# at image-build; rebuilds run /arena/restart.sh which recompiles from the
# writable source tree.
#
# Build context: this dir.

FROM --platform=linux/amd64 debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Build deps (gcc/make + headers, kept for the offline defense rebuild) and the
# runtime serving stack (nginx + spawn-fcgi + fcgiwrap).
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libc6-dev \
        libfcgi-dev libjson-c-dev zlib1g-dev uuid-dev \
        nginx spawn-fcgi fcgiwrap libfcgi-bin libjson-c5 zlib1g libuuid1 \
        python3 python3-pycryptodome \
        openssh-server procps ca-certificates curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# The service user the upstream anti-debug constructors insist on: the CGI binary
# exit(0)s unless euid's pw_name == "reversaar" and cwd == /home/reversaar.
RUN useradd --create-home --home-dir /home/reversaar --shell /bin/bash reversaar
RUN useradd --create-home --shell /bin/bash arena_agent

# Bake the source as a read-only template; a writable copy is made at boot under
# /home/reversaar (where the CGI must run) and the agent edits
# /srv/challenge/reversaar/app (a bind-style symlink target; see entrypoint).
COPY service/ /opt/challenge_src/reversaar/app/

# Build the initial binaries with the FULL upstream codegen (obfuscate + compile
# + forge_crc32 + rc4wrap), proving the pipeline works at image-build time.
COPY build_service.sh /arena/build_service.sh
RUN chmod 555 /arena/build_service.sh \
    && cp -a /opt/challenge_src/reversaar/app /tmp/initbuild \
    && /arena/build_service.sh /tmp/initbuild full \
    && cp /tmp/initbuild/reversaar.cgi /tmp/initbuild/.tmp.bin /opt/challenge_src/reversaar/app/ \
    && rm -rf /tmp/initbuild \
    && chmod -R 555 /opt/challenge_src

COPY restart.sh /arena/restart.sh
COPY checker.sh /arena/checker.sh
COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 555 /arena/restart.sh /arena/checker.sh /arena/entrypoint.sh \
    && chown root:root /arena/restart.sh /arena/checker.sh /arena/entrypoint.sh /arena/build_service.sh

# nginx site: port 7331, static web root + /api via fcgiwrap socket + /userdata
COPY nginx-reversaar.conf /etc/nginx/sites-available/reversaar
RUN rm -f /etc/nginx/sites-enabled/default \
    && ln -sf /etc/nginx/sites-available/reversaar /etc/nginx/sites-enabled/reversaar

RUN mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 7331 22
CMD ["/arena/entrypoint.sh"]
