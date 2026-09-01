FROM --platform=linux/amd64 joomla@sha256:2a32bb358d95627f7c9ef2eb834e61746b4270c367046eea3dbe802d6f16cbac

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl mariadb-client mariadb-server openssh-server python3 \
    && useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /run/joomla \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && rm -rf /var/lib/apt/lists/*

COPY source-primary.tar.gz /tmp/source-primary.tar.gz
RUN echo '9e2f7cb5c88bcac14f643523891c1a55daccab39a6862c614998ec8cfda57606  /tmp/source-primary.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/source-primary.tar.gz -C /usr/src/joomla \
    && rm /tmp/source-primary.tar.gz \
    && test "$(sha256sum /usr/src/joomla/libraries/src/Router/ApiRouter.php | cut -d' ' -f1)" = \
       '3477fb519a5e8ee54a15f79037bb6fc1bcd37e8a08146b8af54e8713cb2cfe69'

COPY prepare_credentials.py /arena/prepare_credentials.py
COPY install.py /arena/install.py
COPY bootstrap_users.py /arena/bootstrap_users.py
COPY entrypoint.sh /arena/entrypoint.sh
COPY restart.sh /arena/restart.sh
RUN chown root:root /arena/prepare_credentials.py /arena/install.py \
        /arena/bootstrap_users.py /arena/entrypoint.sh /arena/restart.sh \
    && chmod 0555 /arena/prepare_credentials.py /arena/install.py \
        /arena/bootstrap_users.py /arena/entrypoint.sh /arena/restart.sh

EXPOSE 80 22
ENTRYPOINT ["/arena/entrypoint.sh"]
