FROM perl@sha256:67a042e56ee3173496a1c0f249286d4b9fedbddae86cdad3e0ec97d12d49b560

ARG DEBIAN_FRONTEND=noninteractive
ARG DEBIAN_SNAPSHOT=20260516T000000Z
RUN printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bullseye main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bullseye-security main" \
      > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/* \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends openssh-server=1:8.4p1-5+deb11u7 \
    && rm -rf /var/lib/apt/lists/*

COPY source-webmin.tar.gz /tmp/source-webmin.tar.gz
COPY source-theme.tar.gz /tmp/source-theme.tar.gz

RUN printf '%s  %s\n' \
       '12027c089becd46847a40a39fb75f556157d705401a65b70cef7a3f500d844aa' \
       '/tmp/source-webmin.tar.gz' | sha256sum -c - \
    && printf '%s  %s\n' \
       'aac67248e557f24ee0bbdc5419f16573d5922cfa151ac1eca338022464643ecc' \
       '/tmp/source-theme.tar.gz' | sha256sum -c - \
    && mkdir -p /opt/webmin-template /opt/webmin-template/authentic-theme \
    && tar -xzf /tmp/source-webmin.tar.gz --strip-components=1 -C /opt/webmin-template \
    && tar -xzf /tmp/source-theme.tar.gz --strip-components=1 -C /opt/webmin-template/authentic-theme \
    && rm /tmp/source-webmin.tar.gz /tmp/source-theme.tar.gz \
    && cd /opt/webmin-template \
    && config_dir=/etc/webmin \
       var_dir=/var/webmin \
       perl=/usr/local/bin/perl \
       autoos=1 \
       port=10000 \
       listen=10000 \
       login=arena_admin \
       password=BuildOnlyWebmin9 \
       ssl=0 \
       atboot=0 \
       theme=authentic-theme \
       session=1 \
       nostart=1 \
       nouninstall=1 \
       noportcheck=1 \
       nochown=1 \
       sh setup.sh \
    && test "$(grep '^theme=' /etc/webmin/config | tail -n 1)" = 'theme=authentic-theme' \
    && mv /etc/webmin /opt/webmin-config-seed \
    && mv /var/webmin /opt/webmin-var-seed \
    && mkdir /etc/webmin /var/webmin

RUN useradd --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /srv/challenge /arena /var/lib/webmin-arena \
    && ssh-keygen -A \
    && sed -i '/^[#[:space:]]*PermitRootLogin[[:space:]]/d' /etc/ssh/sshd_config \
    && printf '\nPermitRootLogin no\n' >> /etc/ssh/sshd_config

COPY entrypoint.sh restart.sh release_broker.pl /arena/
RUN chmod 0755 /arena/entrypoint.sh /arena/restart.sh /arena/release_broker.pl \
    && chown root:root /arena/entrypoint.sh /arena/restart.sh /arena/release_broker.pl

EXPOSE 10000
ENTRYPOINT ["/arena/entrypoint.sh"]
