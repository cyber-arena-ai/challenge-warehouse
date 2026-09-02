FROM composer:1.10.26@sha256:83b881f56dfc2247020fc397c7dc858e638848646e6430371222476b38b78f07 AS composer

FROM php:7.4-cli-bullseye@sha256:620a6b9f4d4feef2210026172570465e9d0c1de79766418d3affd09190a7fda5

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential git libfreetype6-dev libjpeg62-turbo-dev libonig-dev \
       libpng-dev libsqlite3-dev libzip-dev openssh-server unzip \
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
    && mkdir -p /run/sshd /srv/challenge /arena \
    && ssh-keygen -A \
    && sed -i '/^[#[:space:]]*PermitRootLogin[[:space:]]/d' /etc/ssh/sshd_config \
    && printf '\nPermitRootLogin no\n' >> /etc/ssh/sshd_config

COPY entrypoint.sh restart.sh router.php /arena/
RUN chmod 0755 /arena/entrypoint.sh /arena/restart.sh \
    && chmod 0644 /arena/router.php

EXPOSE 8080
ENTRYPOINT ["/arena/entrypoint.sh"]
