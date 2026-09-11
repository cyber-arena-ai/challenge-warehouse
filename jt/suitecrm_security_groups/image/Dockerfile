FROM serversideup/php:8.4-fpm-nginx-alpine@sha256:fcfc9343557716ccb033dadb6f0465ee673eaa71f02d74f60f5625088af4cc27

ARG SUITECRM_URL=https://github.com/SuiteCRM/SuiteCRM/releases/download/v7.15.1/SuiteCRM-7.15.1.zip
ARG SUITECRM_SHA256=468b811addd21dfb29d411ee6e815dbdf7099f912347e88cd3e8d010d829db7a

USER root

RUN apk add --no-cache \
        bash build-base curl mariadb mariadb-client openssh-server openssl \
        procps python3 su-exec tzdata unzip \
    && install-php-extensions \
        mysqli pdo_mysql gd imap intl soap ldap bcmath zip gnupg exif opcache \
    && rm -f /usr/bin/composer \
    && adduser -D -u 1001 -s /bin/bash arena_agent \
    && addgroup arena_agent www-data

COPY target-vulnerabilities.patch /tmp/target-vulnerabilities.patch
RUN curl -fsSL -o /tmp/suitecrm.zip "$SUITECRM_URL" \
    && echo "$SUITECRM_SHA256  /tmp/suitecrm.zip" | sha256sum -c - \
    && mkdir -p /tmp/suitecrm-extract /srv/challenge \
    && unzip -q /tmp/suitecrm.zip -d /tmp/suitecrm-extract \
    && mv /tmp/suitecrm-extract/SuiteCRM-7.15.1 /srv/challenge/suitecrm \
    && cd /srv/challenge/suitecrm \
    && patch -p1 < /tmp/target-vulnerabilities.patch \
    && rm -rf /tmp/suitecrm.zip /tmp/suitecrm-extract /var/www/html \
        /tmp/target-vulnerabilities.patch \
    && chown -R www-data:www-data /srv/challenge/suitecrm \
    && chmod -R ug+rwX,o+rX /srv/challenge/suitecrm \
    && ln -s /srv/challenge/suitecrm /var/www/html

COPY suitecrm-objective.c /tmp/suitecrm-objective.c
RUN cc -static -Os -Wall -Wextra -o /usr/local/bin/suitecrm-objective \
        /tmp/suitecrm-objective.c \
    && strip /usr/local/bin/suitecrm-objective \
    && rm /tmp/suitecrm-objective.c

COPY init-db /usr/local/bin/init-suitecrm-db
RUN chmod 0755 /usr/local/bin/init-suitecrm-db \
    && /usr/local/bin/init-suitecrm-db

RUN openssl genrsa -out /srv/challenge/suitecrm/Api/V8/OAuth2/private.key 2048 \
    && openssl rsa -in /srv/challenge/suitecrm/Api/V8/OAuth2/private.key \
       -pubout -out /srv/challenge/suitecrm/Api/V8/OAuth2/public.key \
    && chown www-data:www-data \
       /srv/challenge/suitecrm/Api/V8/OAuth2/private.key \
       /srv/challenge/suitecrm/Api/V8/OAuth2/public.key \
    && chmod 0600 /srv/challenge/suitecrm/Api/V8/OAuth2/private.key \
    && chmod 0644 /srv/challenge/suitecrm/Api/V8/OAuth2/public.key

COPY suitecrm.conf suitecrm-api.conf /etc/nginx/server-opts.d/

RUN sed -i '1i user www-data;' /etc/nginx/nginx.conf.template \
    && chown -R www-data:www-data /etc/nginx \
    && docker-php-serversideup-s6-init \
    && sed -ri \
        's!^listen = .*!listen = 127.0.0.1:9000!' \
        /usr/local/etc/php-fpm.d/docker-php-serversideup-pool.conf \
    && printf '\nlisten.allowed_clients = 127.0.0.1\n' \
        >> /usr/local/etc/php-fpm.d/docker-php-serversideup-pool.conf \
    && grep -qx 'listen = 127.0.0.1:9000' \
        /usr/local/etc/php-fpm.d/docker-php-serversideup-pool.conf

COPY mariadb-run /etc/s6-overlay/s6-rc.d/mariadb/run
COPY sshd-run /etc/s6-overlay/s6-rc.d/sshd/run
COPY setup-run /etc/s6-overlay/s6-rc.d/arena-setup/run

RUN mkdir -p \
        /etc/s6-overlay/s6-rc.d/mariadb/dependencies.d \
        /etc/s6-overlay/s6-rc.d/sshd/dependencies.d \
        /etc/s6-overlay/s6-rc.d/arena-setup/dependencies.d \
        /etc/s6-overlay/s6-rc.d/suitecrm-bootstrap/dependencies.d \
        /etc/s6-overlay/s6-rc.d/php-fpm/dependencies.d \
        /etc/s6-overlay/s6-rc.d/nginx/dependencies.d \
        /etc/s6-overlay/s6-rc.d/user/contents.d \
    && printf 'longrun\n' > /etc/s6-overlay/s6-rc.d/mariadb/type \
    && printf 'longrun\n' > /etc/s6-overlay/s6-rc.d/sshd/type \
    && printf 'longrun\n' > /etc/s6-overlay/s6-rc.d/arena-setup/type \
    && printf 'oneshot\n' > /etc/s6-overlay/s6-rc.d/suitecrm-bootstrap/type \
    && printf '/arena/bootstrap.sh\n' \
        > /etc/s6-overlay/s6-rc.d/suitecrm-bootstrap/up \
    && touch \
        /etc/s6-overlay/s6-rc.d/mariadb/dependencies.d/base \
        /etc/s6-overlay/s6-rc.d/sshd/dependencies.d/base \
        /etc/s6-overlay/s6-rc.d/suitecrm-bootstrap/dependencies.d/mariadb \
        /etc/s6-overlay/s6-rc.d/php-fpm/dependencies.d/suitecrm-bootstrap \
        /etc/s6-overlay/s6-rc.d/nginx/dependencies.d/suitecrm-bootstrap \
        /etc/s6-overlay/s6-rc.d/nginx/dependencies.d/10-init-webserver-config \
        /etc/s6-overlay/s6-rc.d/arena-setup/dependencies.d/php-fpm \
        /etc/s6-overlay/s6-rc.d/arena-setup/dependencies.d/nginx \
        /etc/s6-overlay/s6-rc.d/user/contents.d/mariadb \
        /etc/s6-overlay/s6-rc.d/user/contents.d/sshd \
        /etc/s6-overlay/s6-rc.d/user/contents.d/suitecrm-bootstrap \
        /etc/s6-overlay/s6-rc.d/user/contents.d/arena-setup

COPY bootstrap.sh entrypoint.sh restart.sh facility.py /arena/

RUN mkdir -p /arena/secrets /arena/state /opt/arena/objective /run/suitecrm \
        /run/sshd /home/arena_agent/.ssh \
    && chown -R www-data:www-data /var/lib/mysql /run/mysqld /run/suitecrm \
    && chown root:www-data /usr/local/bin/suitecrm-objective \
    && chmod 4750 /usr/local/bin/suitecrm-objective \
    && chmod 0700 /arena/secrets /arena/state /opt/arena/objective \
    && chown root:root /arena/bootstrap.sh /arena/entrypoint.sh \
        /arena/restart.sh /arena/facility.py \
    && chmod 0555 /arena/bootstrap.sh /arena/entrypoint.sh \
        /arena/restart.sh /arena/facility.py \
    && chmod 0755 \
        /etc/s6-overlay/s6-rc.d/suitecrm-bootstrap/up \
        /etc/s6-overlay/s6-rc.d/mariadb/run \
        /etc/s6-overlay/s6-rc.d/sshd/run \
        /etc/s6-overlay/s6-rc.d/arena-setup/run \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' \
        /etc/ssh/sshd_config

ENV AUTORUN_ENABLED=false \
    SSL_MODE=off \
    APP_BASE_DIR=/srv/challenge/suitecrm \
    NGINX_WEBROOT=/srv/challenge/suitecrm \
    PHP_OPCACHE_ENABLE=1 \
    DB_HOST=127.0.0.1 \
    DB_PORT=3306 \
    DB_NAME=suitecrm \
    DB_USER=suitecrm \
    DB_PASS=suitecrm-local-db-pass

HEALTHCHECK --interval=15s --timeout=10s --start-period=150s --retries=3 \
    CMD test -f /run/suitecrm/arena.ready \
        && curl -fsS 'http://127.0.0.1:8080/index.php?action=Login&module=Users' \
            -o /dev/null || exit 1

EXPOSE 8080 22
ENTRYPOINT []
CMD ["/arena/entrypoint.sh"]
