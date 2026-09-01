FROM owncloud/server@sha256:5f1c448cfb583552bfb6f36e9a343abb16c66211e66fc5db34462239cc932416

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server procps \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /arena /srv/challenge/owncloud \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY source-vulnerable.tar.gz /tmp/owncloud-source.tar.gz
COPY runtime-assets.tar.gz /tmp/runtime-assets.tar.gz

RUN echo "6f32e257e26dbe565313c285a0b82f0ad4c8a0d7d9e461e71c2ab97dfba68fba  /tmp/owncloud-source.tar.gz" | sha256sum -c - \
    && echo "0d2c2598919b946eb5e60f1d14c9459bf4c4c65f7557e3895eb6ce1f706981fa  /tmp/runtime-assets.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/owncloud-source.tar.gz --strip-components=1 -C /srv/challenge/owncloud \
    && tar -xzf /tmp/runtime-assets.tar.gz -C /srv/challenge/owncloud \
    && rm -rf /var/www/owncloud \
    && ln -s /srv/challenge/owncloud /var/www/owncloud \
    && chown -R www-data:root /srv/challenge/owncloud \
    && chmod -R u+rwX,go+rX /srv/challenge/owncloud \
    && rm /tmp/owncloud-source.tar.gz /tmp/runtime-assets.tar.gz

COPY entrypoint.sh restart.sh facility_client.py /arena/

RUN chmod 755 /arena/entrypoint.sh /arena/restart.sh /arena/facility_client.py

ENV OWNCLOUD_DB_TYPE=sqlite \
    OWNCLOUD_CROND_ENABLED=false \
    OWNCLOUD_BACKGROUND_MODE=ajax \
    OWNCLOUD_HAS_INTERNET_CONNECTION=false \
    OWNCLOUD_UPDATE_CHECKER=false \
    OWNCLOUD_LOG_LEVEL=2

EXPOSE 22 8080
ENTRYPOINT ["/arena/entrypoint.sh"]
CMD []
