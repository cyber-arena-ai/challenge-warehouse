# cyberarena/chal-8-bit-oracle runtime image.
#
# saarCTF 2024 "8-bit-oracle" (a Java magic-8-ball / review oracle on TCP 17280)
# packaged as a self-contained vulbox. Upstream co-locates a MariaDB the Java
# service reaches over a unix socket as user "8BitOracle" (unix_socket auth);
# we bake that DB INTO the image and initialise the app schema + DB user at
# build time so nothing is fetched at runtime (SOP §4).
#
# The JDK stays in the image so the defense flow can recompile (javac) the
# service after an edit; the initial classes/jar are compiled at build time and
# all SQLDriver jars are kept so rebuilds work fully offline. The service is a
# single long-lived multi-threaded listener, so restart.sh runs it as a
# background daemon (no inetd wrapper). Build context: this dir.

FROM --platform=linux/amd64 eclipse-temurin:21-jdk-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server procps python3 ca-certificates \
        mariadb-server mariadb-client \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash arena_agent

# The Java service connects to MariaDB as OS/db user "8BitOracle" via the unix
# socket (junixsocket + unix_socket auth). Create that OS account; the daemon
# runs as it so peer-credential auth matches the DB user of the same name.
RUN useradd --create-home --shell /bin/bash 8BitOracle

# ---- Bake source + pre-built jar as a read-only template -------------------
# A writable copy is made at boot under /srv/challenge so the defender can edit
# and restart.sh can recompile.
COPY service/ /opt/challenge_src/8-bit-oracle/app/
RUN cd /opt/challenge_src/8-bit-oracle/app/_8BitOracle \
    && javac -cp "SQLDriver/*" -sourcepath . -d build src/*.java \
    && (cd build && jar cfm /opt/challenge_src/8-bit-oracle/app/EightBitOracle.jar \
            ../oracle.mf *.class) \
    && cp SQLDriver/*.jar /opt/challenge_src/8-bit-oracle/app/ \
    && chmod -R 555 /opt/challenge_src

# ---- Initialise MariaDB data dir + app schema/user at build time -----------
# mysql_install_db lays down the system tables; then we boot mariadbd once
# offline, create the 8BitOracle unix_socket user + bitoracle DB + app tables,
# and shut it down. At runtime entrypoint just starts mariadbd against this
# pre-initialised datadir.
# One RUN: install system tables, boot mariadbd (background), create the app
# user+schema, VERIFY it, then cleanly shut down and `wait` so InnoDB flushes the
# new `bitoracle` DB to /var/lib/mysql BEFORE the layer is committed. The prior
# version put the shutdown in a SEPARATE RUN, so when the create-RUN ended Docker
# killed the backgrounded mariadbd before it flushed → `bitoracle`/`8BitOracle`
# were silently absent from the image and the service died "Could not connect to
# database" at round-0 plant (the real, deeper half of issue #25). `set -e` + the
# verification SELECT make any future breakage fail the build loudly.
RUN set -eu; \
    mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld; \
    mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=normal >/dev/null; \
    /usr/sbin/mariadbd --user=mysql --skip-networking & \
    MPID=$!; \
    for i in $(seq 1 60); do [ -S /run/mysqld/mysqld.sock ] && break; sleep 0.5; done; \
    printf '%s\n' \
      "CREATE USER IF NOT EXISTS '8BitOracle'@'localhost' IDENTIFIED VIA unix_socket;" \
      "CREATE USER IF NOT EXISTS '8BitOracle' IDENTIFIED VIA unix_socket;" \
      "CREATE DATABASE IF NOT EXISTS bitoracle;" \
      "GRANT ALL ON bitoracle.* TO '8BitOracle'@'localhost';" \
      "GRANT ALL ON bitoracle.* TO '8BitOracle';" \
      "USE bitoracle;" \
      "CREATE TABLE IF NOT EXISTS reviews (id integer PRIMARY KEY AUTO_INCREMENT, review_text text NOT NULL, public_key text NOT NULL);" \
      "CREATE TABLE IF NOT EXISTS states (id integer PRIMARY KEY AUTO_INCREMENT, state text NOT NULL);" \
      | mariadb; \
    mariadb -N -e "SELECT 'bitoracle-init-verified', COUNT(*) FROM bitoracle.reviews"; \
    ( mysqladmin shutdown 2>/dev/null || mariadb-admin shutdown 2>/dev/null || kill "$MPID" ); \
    wait "$MPID" 2>/dev/null || true

COPY restart.sh /arena/restart.sh
COPY checker.sh /arena/checker.sh
RUN chmod 555 /arena/restart.sh /arena/checker.sh \
    && chown root:root /arena/restart.sh /arena/checker.sh

RUN mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 555 /arena/entrypoint.sh && chown root:root /arena/entrypoint.sh

EXPOSE 17280 22
CMD ["/arena/entrypoint.sh"]
