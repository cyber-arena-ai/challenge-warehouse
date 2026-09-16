ARG WORDPRESS_BASE=wordpress:6.9.4-php8.2-apache@sha256:29a3af5db27d8c1716367575280bbf449cd231ced707daf8ce411895c042ed76
ARG NODE_BASE=node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0

FROM ${NODE_BASE} AS source
ARG WORDPRESS_COMMIT=3d199988d6e0e011b0a71c4c58b900cd475dc73d
ARG WORDPRESS_ARCHIVE_SHA256=2125ae23a02c3d3481574135a5a2fc7137eac083a930af258ac43f946bbad1c7
ARG NODE_DEBIAN_SNAPSHOT=20260421T000000Z
WORKDIR /work
RUN sed -i \
      -e "s|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/${NODE_DEBIAN_SNAPSHOT}|" \
      -e "s|http://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/${NODE_DEBIAN_SNAPSHOT}|" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
       ca-certificates=20230311+deb12u1 curl=7.88.1-10+deb12u14 \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL \
       "https://github.com/WordPress/wordpress-develop/archive/${WORDPRESS_COMMIT}.tar.gz" \
       -o /tmp/wordpress.tar.gz \
    && echo "${WORDPRESS_ARCHIVE_SHA256}  /tmp/wordpress.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/wordpress.tar.gz --strip-components=1 -C /work \
    && rm /tmp/wordpress.tar.gz
COPY package-lock.study.json /tmp/package-lock.study.json
RUN cp /tmp/package-lock.study.json package-lock.json \
    && npm ci --no-audit --no-fund \
    && npm run build \
    && test -f build/wp-includes/class-wp-query.php \
    && test -f build/wp-includes/rest-api/class-wp-rest-server.php \
    && test -f build/wp-includes/rest-api.php

FROM ${WORDPRESS_BASE}
ENV DEBIAN_FRONTEND=noninteractive
ENTRYPOINT []

ARG WORDPRESS_DEBIAN_SNAPSHOT=20260518T000000Z
RUN sed -i \
      -e "s|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/${WORDPRESS_DEBIAN_SNAPSHOT}|" \
      -e "s|http://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/${WORDPRESS_DEBIAN_SNAPSHOT}|" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
       ca-certificates=20250419 curl=8.14.1-2+deb13u3 less=668-1 \
       mariadb-client=1:11.8.6-0+deb13u1 \
       mariadb-server=1:11.8.6-0+deb13u1 \
       openssh-server=1:10.0p1-7+deb13u4 procps=2:4.0.4-9 \
       python3=3.13.5-1 rsync=3.4.1+ds1-5+deb13u2 \
    && rm -rf /var/lib/apt/lists/*

# wp-cli is a native WordPress administration surface used only by the trusted
# facility and restart flow.
ARG WP_CLI_VERSION=2.12.0
ARG WP_CLI_SHA256=ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c
RUN curl -fsSL \
      "https://github.com/wp-cli/wp-cli/releases/download/v${WP_CLI_VERSION}/wp-cli-${WP_CLI_VERSION}.phar" \
      -o /usr/local/bin/wp \
    && echo "${WP_CLI_SHA256}  /usr/local/bin/wp" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/wp

RUN rm -rf /opt/wordpress-source /var/www/html/* \
    && mkdir -p /opt/wordpress-source /var/www/html
COPY --from=source --chown=root:root /work/build/ /opt/wordpress-source/
RUN cp -a /opt/wordpress-source/. /var/www/html/ \
    && chown -R www-data:www-data /var/www/html \
    && mkdir -p /run/mysqld \
    && chown -R mysql:mysql /run/mysqld /var/lib/mysql \
    && if [ ! -d /var/lib/mysql/mysql ]; then \
         mariadb-install-db --user=mysql --datadir=/var/lib/mysql \
           --auth-root-authentication-method=normal >/dev/null; \
       fi \
    && { mariadbd --user=mysql --datadir=/var/lib/mysql --port=3306 \
         --bind-address=127.0.0.1 >/var/log/mariadb-build.log 2>&1 & \
       pid=$!; \
       for i in $(seq 1 60); do mysqladmin ping --silent 2>/dev/null && break; sleep 1; done; \
       mysql -e "CREATE DATABASE wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"; \
       mysql -e "CREATE USER 'wp'@'127.0.0.1' IDENTIFIED BY 'wp'; GRANT ALL ON wordpress.* TO 'wp'@'127.0.0.1'; FLUSH PRIVILEGES"; \
       runuser -u www-data -- wp --path=/var/www/html config create \
         --dbname=wordpress --dbuser=wp --dbpass=wp --dbhost=127.0.0.1 \
         --skip-check --skip-salts; \
       for key in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do \
         runuser -u www-data -- wp --path=/var/www/html config set "$key" "bootstrap-$key" --type=constant; \
       done; \
       runuser -u www-data -- wp --path=/var/www/html config set WP_AUTO_UPDATE_CORE false --raw --type=constant; \
       runuser -u www-data -- wp --path=/var/www/html config set AUTOMATIC_UPDATER_DISABLED true --raw --type=constant; \
       runuser -u www-data -- wp --path=/var/www/html config set WP_ENVIRONMENT_TYPE local --type=constant; \
       runuser -u www-data -- wp --path=/var/www/html core install \
         --url=http://localhost --title='Site Journal' --admin_user=site-owner \
         --admin_password='bootstrap-disabled-at-runtime' \
         --admin_email=owner@invalid.example --skip-email; \
       runuser -u www-data -- wp --path=/var/www/html post create \
         --post_type=post --post_status=publish --post_title='Welcome' \
         --post_content='Welcome to the site journal.'; \
       for n in 1 2 3 4 5; do \
         runuser -u www-data -- wp --path=/var/www/html post create \
           --post_type=page --post_status=publish --post_title="Reference $n" \
           --post_content="Public reference page $n."; \
       done; \
       mysqladmin shutdown; \
       wait "$pid" || true; \
       } \
    && chown -R www-data:www-data /var/www/html

RUN useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /var/lib/cyberarena \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && chmod 0700 /var/lib/cyberarena \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY facility.py /arena/facility.py
COPY restart.sh /arena/restart.sh
COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 0555 /arena/facility.py /arena/restart.sh /arena/entrypoint.sh \
    && chown root:root /arena/facility.py /arena/restart.sh /arena/entrypoint.sh

EXPOSE 80 22
CMD ["/arena/entrypoint.sh"]
