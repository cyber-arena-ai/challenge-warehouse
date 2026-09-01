FROM --platform=linux/amd64 php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gcc libc6-dev libfreetype6-dev libjpeg62-turbo-dev \
        libonig-dev libpng-dev libzip-dev mariadb-client mariadb-server \
        openssh-server python3 \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j2 gd mbstring pdo_mysql zip \
    && a2enmod rewrite \
    && sed -ri 's!AllowOverride None!AllowOverride All!g' /etc/apache2/apache2.conf \
    && useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /opt/challenge_src/navigate /usr/local/libexec \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config \
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
RUN gcc -O2 -Wall -Wextra -o /usr/local/libexec/navigate-proof /tmp/proof.c \
    && chown root:root /usr/local/libexec/navigate-proof \
    && chmod 0755 /usr/local/libexec/navigate-proof \
    && rm /tmp/proof.c

COPY configure.py /arena/configure.py
COPY bootstrap.php /arena/bootstrap.php
COPY restart.sh /arena/restart.sh
COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 0555 /arena/configure.py /arena/bootstrap.php /arena/restart.sh /arena/entrypoint.sh \
    && chown root:root /arena/configure.py /arena/bootstrap.php /arena/restart.sh /arena/entrypoint.sh

EXPOSE 80 22
CMD ["/arena/entrypoint.sh"]
