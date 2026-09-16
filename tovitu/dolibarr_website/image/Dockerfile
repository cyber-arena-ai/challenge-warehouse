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

# Debian buster is archived. Resolve the complete dependency closure from one
# immutable snapshot; no package access occurs after image build.
RUN rm -f /etc/apt/sources.list.d/* \
    && printf '%s\n' \
       'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-archive/20250614T182042Z/debian buster main' \
       'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-archive/20250614T182042Z/debian-security buster/updates main' \
       > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
       mariadb-server=1:10.3.39-0+deb10u2 \
       mariadb-client=1:10.3.39-0+deb10u2 \
       openssh-server=1:7.9p1-10+deb10u4 \
       python3=3.7.3-1 \
       procps=2:3.3.15-2 \
       rsync=3.1.3-6 \
       ca-certificates=20200601~deb10u2 \
       curl=7.64.0-4+deb10u9 \
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
    && gcc -O2 -Wall -Wextra -o /usr/local/libexec/dolibarr-proof /tmp/dolibarr-proof.c \
    && chown root:root /usr/local/libexec/dolibarr-proof \
    && chmod 4755 /usr/local/libexec/dolibarr-proof \
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
