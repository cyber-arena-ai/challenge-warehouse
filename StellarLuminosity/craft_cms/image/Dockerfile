# cyberarena/chal-craft-cms runtime image.
#
# Craft CMS 5.6.16 (CVE-2025-32432, pre-auth RCE) collapsed into a single
# container: Apache + PHP 8.3 + Craft + a co-resident MariaDB, plus sshd +
# arena_agent for the DEFENSE workflow. The framework deploys exactly one
# VulboxImage per team, so the vulhub web+db split is merged here.
#
# Craft is composer-installed and headless-`craft install`ed at BUILD time
# (against a build-time MariaDB whose data dir is baked into the image), so
# containers start fast — no install on boot. The flag lives at /flag,
# readable as www-data once the attacker lands RCE.
#
# Build context: this dir (challenges/craft_cms/image/).

FROM --platform=linux/amd64 php:8.3-apache

ENV DEBIAN_FRONTEND=noninteractive

# ── System deps: PHP build libs, MariaDB, sshd, tooling ───────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libjpeg62-turbo-dev libpng-dev libfreetype6-dev libonig-dev \
        libicu-dev libzip-dev \
        mariadb-server mariadb-client \
        openssh-server \
        python3 procps curl ca-certificates \
    && docker-php-ext-install bcmath gd mbstring pdo_mysql intl zip \
    && curl -#sSL -o /usr/local/bin/composer https://getcomposer.org/download/2.9.3/composer.phar \
    && chmod +x /usr/local/bin/composer \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Craft CMS 5.6.16 (vulhub recipe) ─────────────────────────────────────────
RUN set -ex \
    && curl -#sSL https://github.com/craftcms/craft/archive/refs/tags/5.4.0.tar.gz \
        | tar xz --strip-components=1 -C /var/www/html \
    && cd /var/www/html \
    && sed -i 's|"craftcms/cms": "^5.0.0"|"craftcms/cms": "5.6.16"|g' composer.json \
    && sed -i 's|"craftcms/cms": "^5.0.0"|"craftcms/cms": "5.6.16"|g' composer.json.default \
    && composer config audit.block-insecure false \
    && composer install --no-scripts --no-interaction \
    && mv .env.example.dev .env \
    && rm composer.json \
    && mv composer.json.default composer.json \
    && composer dump-autoload -o \
    && sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/html/web|g' /etc/apache2/sites-enabled/000-default.conf \
    && a2enmod rewrite

# ── .env: point Craft at the co-resident MariaDB + a stable security key ──────
# Override only the keys we must, in-place, whether or not the skeleton
# already defines them — leaving the skeleton's dev defaults (CRAFT_ENVIRONMENT
# / devMode) untouched, since that is the exact config the exploit is proven
# against. The only essential change is DB_SERVER db -> 127.0.0.1.
RUN set -ex; \
    cd /var/www/html; \
    set_env() { \
        key="${1%%=*}"; \
        if grep -q "^${key}=" .env; then \
            sed -i "s|^${key}=.*|$1|" .env; \
        else \
            echo "$1" >> .env; \
        fi; \
    }; \
    set_env "CRAFT_APP_ID=arena-craft-cms"; \
    set_env "CRAFT_SECURITY_KEY=arena-craft-cms-fixed-key-not-for-prod-0001"; \
    set_env "CRAFT_DB_DRIVER=mysql"; \
    set_env "CRAFT_DB_SERVER=127.0.0.1"; \
    set_env "CRAFT_DB_PORT=3306"; \
    set_env "CRAFT_DB_DATABASE=craftcms"; \
    set_env "CRAFT_DB_USER=craft"; \
    set_env "CRAFT_DB_PASSWORD=craftpass"; \
    set_env "CRAFT_DB_TABLE_PREFIX="; \
    set_env "CRAFT_ALLOW_ADMIN_CHANGES=true"; \
    set_env "PRIMARY_SITE_URL=http://localhost"

# ── Build-time headless Craft install (bakes the installed DB into the image) ─
# `craft install/craft` option names differ across Craft point releases
# (kebab vs camelCase); we can't build-verify here, so try kebab then fall
# back to camelCase. The fallback only fires on arg-parse failure, before any
# DB write, so it can't double-install.
RUN set -ex; \
    mkdir -p /run/mysqld; \
    chown -R mysql:mysql /run/mysqld /var/lib/mysql; \
    if [ ! -d /var/lib/mysql/mysql ]; then \
        mariadb-install-db --user=mysql --datadir=/var/lib/mysql \
            --auth-root-authentication-method=normal >/dev/null; \
    fi; \
    mariadbd --user=mysql --datadir=/var/lib/mysql --port=3306 \
        >/var/log/mariadb-build.log 2>&1 & \
    for i in $(seq 1 60); do mysqladmin ping --silent 2>/dev/null && break; sleep 1; done; \
    mysql -e "CREATE DATABASE IF NOT EXISTS craftcms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"; \
    mysql -e "CREATE USER IF NOT EXISTS 'craft'@'127.0.0.1' IDENTIFIED BY 'craftpass'; GRANT ALL PRIVILEGES ON craftcms.* TO 'craft'@'127.0.0.1';"; \
    mysql -e "CREATE USER IF NOT EXISTS 'craft'@'localhost' IDENTIFIED BY 'craftpass'; GRANT ALL PRIVILEGES ON craftcms.* TO 'craft'@'localhost'; FLUSH PRIVILEGES;"; \
    cd /var/www/html; \
    ( CRAFT_ALLOW_SUPERUSER=1 php craft install/craft --interactive=0 \
        --email=admin@arena.local --username=admin --password='Arena_CTF_2026!' \
        --site-name=Arena --site-url='http://localhost' --language=en-US \
      || CRAFT_ALLOW_SUPERUSER=1 php craft install/craft --interactive=0 \
        --email=admin@arena.local --username=admin --password='Arena_CTF_2026!' \
        --siteName=Arena --siteUrl='http://localhost' --language=en-US ); \
    mysqladmin shutdown; \
    for i in $(seq 1 20); do mysqladmin ping --silent 2>/dev/null || break; sleep 1; done; \
    chown -R www-data:www-data /var/www/html; \
    touch /opt/.craft_installed

# ── Baseline flag (framework re-plants the real one each round) ────────────────
RUN printf 'FLAG{00000000000000000000000000000000}' > /flag && chmod 644 /flag

# ── Defender's editable source: pristine read-only copy of the front controller ─
RUN mkdir -p /opt/challenge_src/craft_cms \
    && cp /var/www/html/web/index.php /opt/challenge_src/craft_cms/index.php \
    && chmod -R 555 /opt/challenge_src/craft_cms

# ── arena_agent + sshd (non-root login only; key provisioned at deploy) ───────
RUN useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

# ── PHP overrides: long transforms + pin sessions to /tmp (exploit + sanity) ───
RUN { \
        echo "max_execution_time = 300"; \
        echo "ignore_user_abort = On"; \
        echo "session.save_path = \"/tmp\""; \
    } > /usr/local/etc/php/conf.d/zz-arena.ini

# ── Framework scripts: root-owned 555 (agent reads + execs, cannot modify) ────
COPY restart.sh /arena/restart.sh
COPY checker.sh /arena/checker.sh
RUN chmod 555 /arena/restart.sh /arena/checker.sh \
    && chown root:root /arena/restart.sh /arena/checker.sh

COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 555 /arena/entrypoint.sh && chown root:root /arena/entrypoint.sh

EXPOSE 80 22

CMD ["/arena/entrypoint.sh"]
