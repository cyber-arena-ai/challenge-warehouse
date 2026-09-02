# Pinned upstream application and build inputs. Nothing is fetched after build.
FROM --platform=linux/amd64 php@sha256:d2d7559c815220accfb1b48704a1ce59623aa21f7d2dcc9bff13838749a678d4

# thexerteproject/xerteonlinetoolkits @ 4e40f8030a2e3267267db7ce03e0ff57270be6f5
ARG SOURCE_URL=https://github.com/thexerteproject/xerteonlinetoolkits/archive/4e40f8030a2e3267267db7ce03e0ff57270be6f5.tar.gz
ARG SOURCE_SHA256=05d9865f1980e320915c1326656a38396cb47fc83443847334de9766e5375f6c

ENV XERTE_ROOT=/srv/challenge/xerte \
    XERTE_DB_NAME=toolkits_data \
    XERTE_DB_USER=xerte \
    XERTE_DB_PASS=xerte-db-pass \
    DEBIAN_FRONTEND=noninteractive

RUN sed -i \
        -e 's#http://deb.debian.org/debian-security#http://snapshot.debian.org/archive/debian-security/20260824T000000Z#' \
        -e 's#http://deb.debian.org/debian#http://snapshot.debian.org/archive/debian/20260824T000000Z#' \
        /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' \
        > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419~deb12u1 \
        curl=7.88.1-10+deb12u15 \
        mariadb-server=1:10.11.18-0+deb12u1 \
        mariadb-client=1:10.11.18-0+deb12u1 \
        openssh-server=1:9.2p1-2+deb12u10 \
        procps=2:4.0.2-3 \
        psmisc=23.6-1 \
        util-linux=2.38.1-5+deb12u3 \
        libcurl4-openssl-dev=7.88.1-10+deb12u15 \
        libfreetype6-dev=2.12.1+dfsg-5+deb12u4 \
        libjpeg62-turbo-dev=1:2.1.5-2 \
        libonig-dev=6.9.8-1 \
        libpng-dev=1.6.39-2+deb12u5 \
        libxml2-dev=2.9.14+dfsg-1.3~deb12u6 \
        libzip-dev=1.7.3-1+b1 \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j2 curl gd mbstring mysqli pdo_mysql simplexml xml zip \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# Pinned application source, served directly from the defender-editable tree.
RUN mkdir -p "$XERTE_ROOT" \
    && curl -fsSL -o /tmp/xerte.tar.gz "$SOURCE_URL" \
    && echo "$SOURCE_SHA256  /tmp/xerte.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/xerte.tar.gz --strip-components=1 -C "$XERTE_ROOT" \
    && rm /tmp/xerte.tar.gz \
    && cp "$XERTE_ROOT/auth_config.php.dist" "$XERTE_ROOT/auth_config.php" \
    && printf '%s\n' \
        '<?php' \
        "\$xerte_toolkits_site->database_type = 'mysql';" \
        "\$xerte_toolkits_site->database_host = 'localhost';" \
        "\$xerte_toolkits_site->database_username = '$XERTE_DB_USER';" \
        "\$xerte_toolkits_site->database_password = '$XERTE_DB_PASS';" \
        "\$xerte_toolkits_site->database_name = '$XERTE_DB_NAME';" \
        "\$xerte_toolkits_site->database_table_prefix = '';" \
        > "$XERTE_ROOT/database.php" \
    && mkdir -p "$XERTE_ROOT/USER-FILES" "$XERTE_ROOT/error_logs" "$XERTE_ROOT/import"

# XAMPP-like deployment: .php4 is handled by PHP, and the web root is writable
# by the Apache identity after setup (see _maintainer/README.md).
COPY apache/ /etc/apache2/conf-available/
COPY php/xerte.ini /usr/local/etc/php/conf.d/xerte.ini
RUN a2enconf xerte-servername xerte-php4 xerte-site xerte-setup-lockdown \
    && sed -i "s#/var/www/html#$XERTE_ROOT#g" /etc/apache2/sites-available/000-default.conf

# Local database: schema baked so first boot needs no network and no fetch.
RUN mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld \
    && ([ -d /var/lib/mysql/mysql ] \
        || mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null) \
    && (mariadbd --user=mysql --skip-networking &) \
    && for i in $(seq 1 60); do mariadb-admin ping >/dev/null 2>&1 && break; sleep 1; done \
    && mariadb -e "CREATE DATABASE \`$XERTE_DB_NAME\`; \
        CREATE USER '$XERTE_DB_USER'@'localhost' IDENTIFIED BY '$XERTE_DB_PASS'; \
        GRANT ALL ON \`$XERTE_DB_NAME\`.* TO '$XERTE_DB_USER'@'localhost';" \
    && sed -e "s/<databasename>/$XERTE_DB_NAME/g" -e 's/\$//g' \
        "$XERTE_ROOT/setup/basic.sql" | mariadb "$XERTE_DB_NAME" \
    && mariadb-admin shutdown \
    && for i in $(seq 1 60); do mariadb-admin ping >/dev/null 2>&1 || break; sleep 1; done \
    && chown -R mysql:mysql /var/lib/mysql

COPY catflag.c /tmp/catflag.c
RUN gcc -Os -Wall -Wextra -o /usr/local/bin/catflag /tmp/catflag.c \
    && strip /usr/local/bin/catflag \
    && chown root:root /usr/local/bin/catflag \
    && chmod 4755 /usr/local/bin/catflag \
    && rm /tmp/catflag.c

COPY entrypoint.sh restart.sh facility.sh /arena/
RUN adduser --disabled-password --gecos "" --uid 1001 arena_agent \
    && adduser arena_agent www-data \
    && mkdir -p /arena/state /arena/secrets /var/lib/arena/command /run/sshd \
    && chown root:root /arena/entrypoint.sh /arena/restart.sh /arena/facility.sh \
    && chmod 0555 /arena/entrypoint.sh /arena/restart.sh /arena/facility.sh \
    && chmod 0700 /arena/state /arena/secrets /var/lib/arena/command \
    && (cd "$XERTE_ROOT" && find . -name '*.php' -not -path './vendor/*' \
        -not -path './USER-FILES/*' -printf '%P\n' | sort > /arena/php-manifest) \
    && sed -i '/^library\/Xerte\/Authentication\/OAuth2\/lib\/random_int.php$/d' \
        /arena/php-manifest \
    && chmod 0444 /arena/php-manifest \
    && chown -R arena_agent:www-data "$XERTE_ROOT" \
    && chmod -R ug+rwX "$XERTE_ROOT" \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 80 22
WORKDIR /srv/challenge/xerte
ENTRYPOINT []
CMD ["/arena/entrypoint.sh"]
