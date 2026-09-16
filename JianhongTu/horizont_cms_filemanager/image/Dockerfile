FROM composer:1.10.26@sha256:83b881f56dfc2247020fc397c7dc858e638848646e6430371222476b38b78f07 AS composer

FROM php:7.4-cli-bullseye@sha256:620a6b9f4d4feef2210026172570465e9d0c1de79766418d3affd09190a7fda5

ARG DEBIAN_FRONTEND=noninteractive
RUN sed -i \
        -e 's#http://deb.debian.org/debian-security#http://snapshot.debian.org/archive/debian-security/20260824T000000Z#' \
        -e 's#http://security.debian.org/debian-security#http://snapshot.debian.org/archive/debian-security/20260824T000000Z#' \
        -e 's#http://deb.debian.org/debian#http://snapshot.debian.org/archive/debian/20260824T000000Z#' \
        /etc/apt/sources.list \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' \
        > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential=12.9 \
       git=1:2.30.2-1+deb11u5 \
       libfreetype6-dev=2.10.4+dfsg-1+deb11u2 \
       libjpeg62-turbo-dev=1:2.0.6-4 \
       libonig-dev=6.9.6-1.1 \
       libpng-dev=1.6.37-3+deb11u4 \
       libsqlite3-dev=3.34.1-3+deb11u1 \
       libzip-dev=1.7.3-1 \
       openssh-server=1:8.4p1-5+deb11u7 \
       procps=2:3.3.17-5 \
       unzip=6.0-26+deb11u2 \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j2 gd mbstring pdo_sqlite zip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer /usr/bin/composer /usr/local/bin/composer
WORKDIR /opt/horizont
COPY source-primary.tar.gz /tmp/source-primary.tar.gz
RUN printf '%s  %s\n' \
       'e0cead28dbeb7cbcb23dbf898536e9a942d8626f7ef958a1764bad41898f710c' \
       '/tmp/source-primary.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/source-primary.tar.gz --strip-components=1 \
    && rm /tmp/source-primary.tar.gz \
    && sed -i \
       's#https://github.com/damiencriado/zipper-l6.git#https://github.com/Chumper/Zipper.git#g; s#https://api.github.com/repos/damiencriado/zipper-l6/zipball/#https://api.github.com/repos/Chumper/Zipper/zipball/#g' \
       composer.lock \
    && COMPOSER_ALLOW_SUPERUSER=1 composer install \
       --no-dev --no-interaction --prefer-dist --no-progress \
    && mkdir -p storage/framework/cache storage/framework/sessions \
       storage/framework/views storage/framework/upgrade/cache database

COPY proof.c /tmp/proof.c
RUN gcc -O2 -Wall -Wextra -o /usr/local/bin/horizont-proof /tmp/proof.c \
    && rm /tmp/proof.c \
    && chown root:www-data /usr/local/bin/horizont-proof \
    && chmod 4750 /usr/local/bin/horizont-proof \
    && useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /srv/challenge /srv/runtime/horizont/generations /arena \
    && ssh-keygen -A \
    && sed -i '/^[#[:space:]]*PermitRootLogin[[:space:]]/d' /etc/ssh/sshd_config \
    && printf '\nPermitRootLogin no\n' >> /etc/ssh/sshd_config

COPY entrypoint.sh restart.sh router.php /arena/
RUN chmod 0755 /arena/entrypoint.sh /arena/restart.sh \
    && chmod 0644 /arena/router.php

EXPOSE 8080
ENTRYPOINT ["/arena/entrypoint.sh"]
