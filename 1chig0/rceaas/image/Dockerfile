# cyberarena/chal-rceaas runtime image.
#
# saarCTF 2025 "RCEaaS" (Rust fake-Windows shell jail) packaged as a
# self-contained vulbox. The generic inetd wrapper replaces the upstream socat
# unit. The Rust toolchain stays in the image so the defense flow can rebuild
# the binary (SOP §4); the initial binary is compiled at build time and all
# crate deps are cached in CARGO_HOME so rebuilds work fully offline. Build
# context: this dir.

FROM --platform=linux/amd64 rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server procps python3 ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent

# Bake source + pre-built binary as a read-only template; a writable copy is
# made at boot. `cargo build` here also populates the CARGO_HOME registry cache
# so the offline defense rebuild has every dependency locally.
COPY service/ /opt/challenge_src/rceaas/app/
RUN cd /opt/challenge_src/rceaas/app && cargo build --release \
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

EXPOSE 1835 22
CMD ["/arena/entrypoint.sh"]
