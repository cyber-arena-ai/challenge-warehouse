# cyberarena/chal-wp2shell runtime image.
#
# WordPress 6.9.4 (CVE-2026-63030 + CVE-2026-60137, pre-auth SQLi via a REST
# batch-endpoint route-confusion) collapsed into a single container: Apache +
# PHP 8.2 + WordPress core + a co-resident MariaDB, plus sshd + arena_agent for
# the DEFENSE workflow. The framework deploys exactly one VulboxImage per team.
#
# MariaDB stands in for the upstream's MySQL 8 — same SQL dialect for this
# bug's purposes, apt-installable on the base image's Debian bookworm without
# adding Oracle's APT repo (this repo's craft-cms challenge sets the same
# precedent). See _maintainer/README.md.
#
# WordPress is installed (wp-cli, non-interactive) against a BUILD-TIME
# MariaDB whose datadir is baked into the image, so containers start fast —
# no install-on-boot. The flag lives in wp_options (option_name
# cyberarena_flag), readable through the SQLi primitive itself; no RCE
# required.
#
# Build context: this dir (StellarLuminosity/wp2shell/image/).

FROM --platform=linux/amd64 wordpress:6.9.4-php8.2-apache

ENV DEBIAN_FRONTEND=noninteractive

# The base image sets its own ENTRYPOINT (docker-entrypoint.sh, an
# env-var-driven wp-config generator + DB-wait). We replace it below with our
# own baked-install entrypoint — reset here so a stray CMD never gets handed
# to the inherited one.
ENTRYPOINT []

# ── System deps: MariaDB, sshd, tooling ────────────────────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        mariadb-server mariadb-client \
        openssh-server \
        python3 procps curl ca-certificates less \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── wp-cli ──────────────────────────────────────────────────────────────────
RUN curl -#sSL -o /usr/local/bin/wp \
        https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    && chmod +x /usr/local/bin/wp

# ── Build-time headless WordPress install (bakes the installed DB into the image) ─
# WP_CLI must not run as root; www-data owns /var/www/html already.
RUN set -ex; \
    mkdir -p /run/mysqld; \
    chown -R mysql:mysql /run/mysqld /var/lib/mysql; \
    if [ ! -d /var/lib/mysql/mysql ]; then \
        mariadb-install-db --user=mysql --datadir=/var/lib/mysql \
            --auth-root-authentication-method=normal >/dev/null; \
    fi; \
    mariadbd --user=mysql --datadir=/var/lib/mysql --port=3306 --skip-networking=0 --bind-address=127.0.0.1 \
        >/var/log/mariadb-build.log 2>&1 & \
    for i in $(seq 1 60); do mysqladmin ping --silent 2>/dev/null && break; sleep 1; done; \
    mysql -e "CREATE DATABASE IF NOT EXISTS wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"; \
    mysql -e "CREATE USER IF NOT EXISTS 'wp'@'127.0.0.1' IDENTIFIED BY 'wp'; GRANT ALL PRIVILEGES ON wordpress.* TO 'wp'@'127.0.0.1';"; \
    mysql -e "CREATE USER IF NOT EXISTS 'wp'@'localhost' IDENTIFIED BY 'wp'; GRANT ALL PRIVILEGES ON wordpress.* TO 'wp'@'localhost'; FLUSH PRIVILEGES;"; \
    cd /var/www/html; \
    chown -R www-data:www-data /var/www/html; \
    su -s /bin/bash www-data -c "wp config create \
        --dbname=wordpress --dbuser=wp --dbpass=wp --dbhost=127.0.0.1 \
        --path=/var/www/html --skip-check"; \
    su -s /bin/bash www-data -c "wp config set WP_AUTO_UPDATE_CORE false --raw --type=constant --path=/var/www/html"; \
    su -s /bin/bash www-data -c "wp config set AUTOMATIC_UPDATER_DISABLED true --raw --type=constant --path=/var/www/html"; \
    su -s /bin/bash www-data -c "wp core install --path=/var/www/html \
        --url=http://localhost --title='Arena' \
        --admin_user=admin --admin_password='Arena_CTF_2026!' \
        --admin_email=admin@arena.local --skip-email"; \
    su -s /bin/bash www-data -c "wp post create --path=/var/www/html \
        --post_title='Hello World' --post_status=publish --post_type=post \
        --post_content='A public post on this site.' --porcelain"; \
    su -s /bin/bash www-data -c "wp post create --path=/var/www/html \
        --post_title='Secret Post' --post_status=private --post_type=post \
        --post_content='Only an authenticated admin should be able to read this.' --porcelain"; \
    su -s /bin/bash www-data -c "wp option update cyberarena_flag 'FLAG{00000000000000000000000000000000}' --path=/var/www/html --autoload=no"; \
    mysqladmin shutdown; \
    for i in $(seq 1 20); do mysqladmin ping --silent 2>/dev/null || break; sleep 1; done; \
    chown -R www-data:www-data /var/www/html; \
    touch /opt/.wp_installed

# ── Defender's editable source: pristine read-only copies of the two vulnerable core files ─
RUN mkdir -p /opt/challenge_src/wp2shell \
    && cp /var/www/html/wp-includes/class-wp-query.php /opt/challenge_src/wp2shell/class-wp-query.php \
    && cp /var/www/html/wp-includes/rest-api/class-wp-rest-server.php /opt/challenge_src/wp2shell/class-wp-rest-server.php \
    && chmod -R 555 /opt/challenge_src/wp2shell

# ── arena_agent + sshd (non-root login only; key provisioned at deploy) ───────
RUN useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

# ── Framework scripts: root-owned 555 (agent reads + execs, cannot modify) ────
COPY restart.sh /arena/restart.sh
RUN chmod 555 /arena/restart.sh && chown root:root /arena/restart.sh

COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 555 /arena/entrypoint.sh && chown root:root /arena/entrypoint.sh

EXPOSE 80 22

CMD ["/arena/entrypoint.sh"]
