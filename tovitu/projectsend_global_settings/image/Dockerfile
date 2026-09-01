# Exact ProjectSend repair parent 675d6d3f2124a4a25ef907b44ceb240003315e46.

FROM --platform=linux/amd64 composer@sha256:5248900ab8b5f7f880c2d62180e40960cd87f60149ec9a1abfd62ac72a02577c AS composer

FROM --platform=linux/amd64 php@sha256:a935f4a5717427519337269d5d1c89968cc27ab84d1c8d5d7b5363672d800cd5

USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       mariadb-server=1:10.11.18-0+deb12u1 \
       openssh-server=1:9.2p1-2+deb12u10 \
       rsync=3.2.7-1+deb12u6 \
       python3 procps curl ca-certificates \
       libfreetype6-dev libjpeg62-turbo-dev libonig-dev libpng-dev libzip-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j2 exif gd mbstring pdo_mysql zip \
    && rm -rf /var/lib/apt/lists/* /var/lib/mysql/*

COPY --from=composer /usr/bin/composer /usr/bin/composer
COPY source-vulnerable.tar.gz /tmp/projectsend-source.tar.gz
RUN echo "c171f013a9ac84178d3bae23e324d3a0bae13084020411ef0618e01964bebdcd  /tmp/projectsend-source.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/challenge_src/projectsend \
    && tar -xzf /tmp/projectsend-source.tar.gz --strip-components=1 -C /opt/challenge_src/projectsend \
    && rm /tmp/projectsend-source.tar.gz \
    && cd /opt/challenge_src/projectsend \
    && composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader

RUN useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /run/mysqld /arena/private /srv/challenge \
    && mkdir -p /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && printf '%s\n' 'ServerName localhost' > /etc/apache2/conf-available/projectsend-servername.conf \
    && a2enconf projectsend-servername

COPY sys.config.php /arena/sys.config.php
COPY bootstrap.py /arena/bootstrap.py
COPY sync-source.sh /arena/sync-source.sh
COPY entrypoint.sh /arena/entrypoint.sh
COPY restart.sh /arena/restart.sh
RUN chown root:root /arena/* \
    && chmod 444 /arena/sys.config.php \
    && chmod 555 /arena/bootstrap.py /arena/sync-source.sh /arena/entrypoint.sh /arena/restart.sh

EXPOSE 80 22
ENTRYPOINT ["/arena/entrypoint.sh"]
CMD []
