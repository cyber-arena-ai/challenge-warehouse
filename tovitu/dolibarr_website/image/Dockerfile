# Dolibarr exact repair parent a633766b23e25f7fce632a1c7c7bf6c7de827e9d.
# Apache, PHP, MariaDB, SSH, editable source, and the execution proof operation
# are deliberately co-resident because the arena deploys one image per service.

FROM --platform=linux/amd64 tuxgasy/dolibarr@sha256:09b5304578c0c2daadf9bf83c79fcbb64eff81d5f7486cca5c58627fc3a202e5

USER root
ENV DEBIAN_FRONTEND=noninteractive \
    DOLI_VERSION=16.0.5 \
    DOLI_INSTALL_AUTO=1 \
    DOLI_DB_TYPE=mysqli \
    DOLI_DB_HOST=127.0.0.1 \
    DOLI_DB_HOST_PORT=3306 \
    DOLI_DB_NAME=dolidb \
    DOLI_DB_USER=doli \
    DOLI_DB_PASSWORD=doli_local_database_3b8e \
    DOLI_ADMIN_LOGIN=arena-admin \
    DOLI_URL_ROOT=http://localhost \
    DOLI_NOCSRFCHECK=0 \
    DOLI_LANG=en_US

# Debian buster is archived. Pin the top-level runtime packages at the versions
# retained by that immutable archive; no package access occurs after image build.
RUN sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g' /etc/apt/sources.list \
    && sed -i '/buster-updates/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
       mariadb-server=1:10.3.39-0+deb10u2 \
       mariadb-client=1:10.3.39-0+deb10u2 \
       openssh-server=1:7.9p1-10+deb10u4 \
       python3 procps rsync ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ARG DOLIBARR_COMMIT=a633766b23e25f7fce632a1c7c7bf6c7de827e9d
ARG DOLIBARR_ARCHIVE_SHA256=7782a31a781cd0a3fe33174011ff76eafc3740f073314298853fc779e7339dda
RUN curl -fsSL "https://github.com/Dolibarr/dolibarr/archive/${DOLIBARR_COMMIT}.tar.gz" -o /tmp/dolibarr.tar.gz \
    && echo "${DOLIBARR_ARCHIVE_SHA256}  /tmp/dolibarr.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/challenge_src/dolibarr \
    && tar -xzf /tmp/dolibarr.tar.gz --strip-components=1 -C /opt/challenge_src/dolibarr \
    && rm /tmp/dolibarr.tar.gz

COPY proof.c /tmp/dolibarr-proof.c
RUN mkdir -p /usr/local/libexec \
    && gcc -O2 -Wall -Wextra -o /usr/local/libexec/dolibarr-proof-template /tmp/dolibarr-proof.c \
    && chown root:root /usr/local/libexec/dolibarr-proof-template \
    && chmod 755 /usr/local/libexec/dolibarr-proof-template \
    && rm /tmp/dolibarr-proof.c

RUN useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /run/mysqld /arena/private \
    && mkdir -p /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY entrypoint.sh /arena/entrypoint.sh
COPY restart.sh /arena/restart.sh
RUN chown root:root /arena/entrypoint.sh /arena/restart.sh \
    && chmod 555 /arena/entrypoint.sh /arena/restart.sh

EXPOSE 80 22
ENTRYPOINT ["/arena/entrypoint.sh"]
CMD []
