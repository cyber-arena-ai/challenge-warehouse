FROM --platform=linux/amd64 php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d

ENV DEBIAN_FRONTEND=noninteractive

RUN printf '%s\n' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260824T000000Z bullseye main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260824T000000Z bullseye-security main' \
        > /etc/apt/sources.list \
    && { [ ! -d /etc/apt/sources.list.d ] \
        || find /etc/apt/sources.list.d -type f -delete; } \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419~deb12u1~deb11u1 \
        curl=7.74.0-1.3+deb11u16 \
        gcc=4:10.2.1-1 \
        libc6-dev=2.31-13+deb11u14 \
        libfreetype6-dev=2.10.4+dfsg-1+deb11u2 \
        libjpeg62-turbo-dev=1:2.0.6-4 \
        libonig-dev=6.9.6-1.1 \
        libpng-dev=1.6.37-3+deb11u4 \
        libzip-dev=1.7.3-1 \
        mariadb-client=1:10.5.29-0+deb11u1 \
        mariadb-server=1:10.5.29-0+deb11u1 \
        openssh-server=1:8.4p1-5+deb11u7 \
        python3=3.9.2-3 \
        util-linux=2.36.1-8+deb11u2 \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j2 gd mbstring pdo_mysql zip \
    && test -x /usr/bin/flock \
    && a2enmod rewrite \
    && sed -ri 's!AllowOverride None!AllowOverride All!g' /etc/apache2/apache2.conf \
    && useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /opt/challenge_src/navigate \
        /srv/runtime/navigate/generations \
        /var/lib/navigate-proof/contexts \
    && chown root:root /srv/runtime/navigate /srv/runtime/navigate/generations \
        /var/lib/navigate-proof /var/lib/navigate-proof/contexts \
    && chmod 0700 /var/lib/navigate-proof /var/lib/navigate-proof/contexts \
    && : > /var/lib/navigate-proof/issued.history \
    && printf '%s\n' navigate-proof-v1 > /var/lib/.navigate-proof.initialized \
    && chown root:root /var/lib/navigate-proof/issued.history \
        /var/lib/.navigate-proof.initialized \
    && chmod 0600 /var/lib/navigate-proof/issued.history \
    && chmod 0400 /var/lib/.navigate-proof.initialized \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config \
    && rm -rf /var/lib/apt/lists/*

COPY source-primary.tar.gz /tmp/source-primary.tar.gz
RUN echo '9c66adafdded4f2778fe454938891d790c753cb0eb793137aa11aad63017da67  /tmp/source-primary.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/source-primary.tar.gz -C /opt/challenge_src/navigate \
    && rm /tmp/source-primary.tar.gz \
    && test "$(sha256sum /opt/challenge_src/navigate/login.php | cut -d' ' -f1)" = "99745db427fd226bdde421c66169c93fcc48fa0ae3de7d5e0dcb66114086637b" \
    && test "$(sha256sum /opt/challenge_src/navigate/navigate_upload.php | cut -d' ' -f1)" = "a2c20fa5af2a5ceb542d43f4a33cb944bb3bf716e58c36969c7eb3fc687adc7d"

COPY navigate.sql /opt/navigate.sql
RUN echo 'd03b45854e3e1df397b4bf43436632da7b143075924204d01729b16a2417caef  /opt/navigate.sql' | sha256sum -c -

COPY proof.c /tmp/proof.c
RUN gcc -O2 -Wall -Wextra -o /usr/local/bin/nv-proof /tmp/proof.c \
    && chown root:www-data /usr/local/bin/nv-proof \
    && chmod 4750 /usr/local/bin/nv-proof \
    && rm /tmp/proof.c

COPY configure.py /arena/configure.py
COPY bootstrap.php /arena/bootstrap.php
COPY restart.sh /arena/restart.sh
COPY entrypoint.sh /arena/entrypoint.sh
COPY supervise.py /arena/supervise.py
RUN chmod 0555 /arena/configure.py /arena/bootstrap.php /arena/restart.sh \
        /arena/entrypoint.sh /arena/supervise.py \
    && chown root:root /arena/configure.py /arena/bootstrap.php /arena/restart.sh \
        /arena/entrypoint.sh /arena/supervise.py

EXPOSE 80 22
CMD ["/arena/entrypoint.sh"]
