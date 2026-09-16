FROM serversideup/php:8.4-fpm-nginx-alpine@sha256:fcfc9343557716ccb033dadb6f0465ee673eaa71f02d74f60f5625088af4cc27

ARG SUITECRM_SHA256=fca66c2c94914e6f0b665c171ecec94b2463860f5c1ac4e9e6cccb6de7e95414

USER root

RUN apk add --no-cache \
        bash \
        build-base \
        curl \
        mariadb \
        mariadb-client \
        openssh-server \
        openssl \
        procps-ng \
        python3 \
        su-exec \
        tzdata \
        unzip \
    && install-php-extensions \
        mysqli pdo_mysql gd imap intl soap ldap bcmath zip gnupg-1.5.4 exif opcache \
    && rm -f /usr/bin/composer \
    && adduser -D -u 1001 -s /bin/bash arena_agent

COPY source/SuiteCRM-7.15.0.zip /tmp/suitecrm.zip

RUN echo "$SUITECRM_SHA256  /tmp/suitecrm.zip" | sha256sum -c - \
    && mkdir -p /tmp/suitecrm-extract /srv/challenge \
        /srv/runtime/generations \
    && unzip -q /tmp/suitecrm.zip -d /tmp/suitecrm-extract \
    && mv /tmp/suitecrm-extract/SuiteCRM-7.15.0 /srv/challenge/suitecrm \
    && rm -rf /tmp/suitecrm.zip /tmp/suitecrm-extract /var/www/html \
    && cp -a /srv/challenge/suitecrm /srv/runtime/generations/image \
    && chown -R arena_agent:arena_agent /srv/challenge/suitecrm \
    && chmod -R u+rwX,go+rX /srv/challenge/suitecrm \
    && chown -R root:root /srv/runtime/generations/image \
    && chmod -R u+rwX,go+rX /srv/runtime/generations/image \
    && ln -s /srv/runtime/generations/image /srv/runtime/current \
    && ln -s /srv/runtime/generations/image /srv/runtime/last-good \
    && ln -s /srv/runtime/current /var/www/html

COPY suitecrm-objective.c /tmp/suitecrm-objective.c
RUN cc -static -Os -Wall -Wextra -o /usr/local/bin/suitecrm-objective \
        /tmp/suitecrm-objective.c \
    && strip /usr/local/bin/suitecrm-objective \
    && rm /tmp/suitecrm-objective.c

COPY init-db /usr/local/bin/init-suitecrm-db
RUN chmod 0755 /usr/local/bin/init-suitecrm-db \
    && /usr/local/bin/init-suitecrm-db

RUN openssl genrsa -out /srv/runtime/generations/image/Api/V8/OAuth2/private.key 2048 \
    && openssl rsa -in /srv/runtime/generations/image/Api/V8/OAuth2/private.key \
       -pubout -out /srv/runtime/generations/image/Api/V8/OAuth2/public.key \
    && chown root:www-data \
       /srv/runtime/generations/image/Api/V8/OAuth2/private.key \
       /srv/runtime/generations/image/Api/V8/OAuth2/public.key \
    && chmod 0600 /srv/runtime/generations/image/Api/V8/OAuth2/private.key \
    && chmod 0644 /srv/runtime/generations/image/Api/V8/OAuth2/public.key

COPY suitecrm.conf suitecrm-api.conf /etc/nginx/server-opts.d/

# SuiteCRM compares modifying-form Referers with PHP's SERVER_NAME. Reflect the
# request host so its native same-origin check works behind the arena TCP ingress.
RUN grep -Fqx 'fastcgi_param  SERVER_NAME        $server_name;' \
        /etc/nginx/fastcgi_params \
    && sed -i \
        's/fastcgi_param  SERVER_NAME        $server_name;/fastcgi_param  SERVER_NAME        $host;/' \
        /etc/nginx/fastcgi_params \
    && grep -Fqx 'fastcgi_param  SERVER_NAME        $host;' \
        /etc/nginx/fastcgi_params \
    && sed -i '1i user www-data;' /etc/nginx/nginx.conf.template \
    && chown -R www-data:www-data /etc/nginx \
    && docker-php-serversideup-s6-init

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

COPY bootstrap.sh entrypoint.sh finalize-generation.sh normalize-generation.sh \
    restart.sh facility.py /arena/

RUN mkdir -p /arena/secrets /arena/state /opt/arena/objective /run/suitecrm \
        /run/sshd /home/arena_agent/.ssh \
    && chown -R www-data:www-data /var/lib/mysql /run/mysqld /run/suitecrm \
    && chown root:www-data /usr/local/bin/suitecrm-objective \
    && chmod 4750 /usr/local/bin/suitecrm-objective \
    && chmod 0700 /arena/secrets /arena/state /opt/arena/objective \
    && chown root:root /arena/bootstrap.sh /arena/entrypoint.sh \
        /arena/finalize-generation.sh /arena/normalize-generation.sh \
        /arena/restart.sh /arena/facility.py \
    && chmod 0555 /arena/bootstrap.sh /arena/entrypoint.sh \
        /arena/finalize-generation.sh /arena/normalize-generation.sh \
        /arena/restart.sh /arena/facility.py \
    && chmod 0755 \
        /etc/s6-overlay/s6-rc.d/suitecrm-bootstrap/up \
        /etc/s6-overlay/s6-rc.d/mariadb/run \
        /etc/s6-overlay/s6-rc.d/sshd/run \
        /etc/s6-overlay/s6-rc.d/arena-setup/run \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' \
        /etc/ssh/sshd_config

# The base image runs PHP-FPM `ondemand`, which reaps the last pool worker
# after 10s idle, so a healthy SuiteCRM has no UID-82 PHP worker a quarter of
# the time. `dynamic` keeps at least pm.min_spare_servers of them resident.
ENV AUTORUN_ENABLED=false \
    SSL_MODE=off \
    APP_BASE_DIR=/srv/runtime/current \
    NGINX_WEBROOT=/srv/runtime/current \
    PHP_FPM_PM_CONTROL=dynamic \
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
