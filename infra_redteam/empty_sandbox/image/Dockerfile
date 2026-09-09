FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        openssh-server \
        procps \
        python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent \
    && useradd --system --home /nonexistent --shell /usr/sbin/nologin sandbox

RUN mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

RUN mkdir -p /opt/cyberarena-empty-sandbox \
    && chown root:root /opt/cyberarena-empty-sandbox \
    && chmod 755 /opt/cyberarena-empty-sandbox
COPY server.py /opt/cyberarena-empty-sandbox/server.py
RUN chmod 555 /opt/cyberarena-empty-sandbox/server.py

COPY restart.sh /arena/restart.sh
COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 555 /arena/entrypoint.sh /arena/restart.sh

EXPOSE 22 8080
ENTRYPOINT ["/arena/entrypoint.sh"]
