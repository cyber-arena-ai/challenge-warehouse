FROM --platform=linux/amd64 python:3.11.15-slim-bookworm@sha256:77923445c077d8eb971b14b2b114a1d9cd4a87edb4c75654820ca4832ee8cb15

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Pin the OS closure to the snapshot the base image records above each stanza,
# so transitive packages are fixed too; _maintainer/README.md says why not
# version pins. Substituting in place keeps whatever suites and components the
# base declared, and the original is restored so apt in the delivered box is
# unchanged. The count check is a postcondition: every source must be pinned, so
# an unpinned build cannot pass.
RUN cp /etc/apt/sources.list.d/debian.sources /tmp/debian.sources.orig \
    && awk '/^# http:\/\/snapshot\./ { snap = substr($0, 3) } \
            /^URIs:/ && snap { print "URIs: " snap; print "Check-Valid-Until: no"; snap = ""; next } \
            { print }' /tmp/debian.sources.orig > /etc/apt/sources.list.d/debian.sources \
    && [ "$(grep -c '^URIs:' /etc/apt/sources.list.d/debian.sources)" \
        = "$(grep -c '^URIs:[[:space:]]*http://snapshot.debian.org/' /etc/apt/sources.list.d/debian.sources)" ] \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates libcurl4-openssl-dev openssh-server procps util-linux \
    && mv /tmp/debian.sources.orig /etc/apt/sources.list.d/debian.sources \
    && rm -rf /var/lib/apt/lists/*

COPY source-primary.tar.gz /tmp/source-primary.tar.gz
COPY requirements.lock /tmp/requirements.lock
RUN echo "c54ad6027df8e78f80c50c056d65d35b5a9e9a093cb8f0ca05a675918b5304a8  /tmp/source-primary.tar.gz" \
        | sha256sum -c - \
    && mkdir -p /opt/pyload-primary \
    && tar -xzf /tmp/source-primary.tar.gz --strip-components=1 -C /opt/pyload-primary \
    && rm /tmp/source-primary.tar.gz \
    && python -m pip install "setuptools==69.5.1" "wheel==0.43.0" \
    && python -m pip install --no-build-isolation -c /tmp/requirements.lock -e /opt/pyload-primary \
    && grep -v '^#' /tmp/requirements.lock | grep . | sort -f > /tmp/locked.txt \
    && python -m pip freeze --exclude-editable | sort -f > /tmp/frozen.txt \
    && diff /tmp/locked.txt /tmp/frozen.txt \
    && rm /tmp/requirements.lock /tmp/locked.txt /tmp/frozen.txt \
    && mkdir -p /opt/challenge_src \
    && cp -a /opt/pyload-primary /opt/challenge_src/pyload \
    && chmod -R a-w /opt/challenge_src/pyload

RUN useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin pyload \
    && useradd --uid 1001 --create-home --shell /bin/bash arena_agent

RUN mkdir -p /srv/pyload/u /srv/pyload/s /srv/pyload/t \
    && (timeout 20 pyload --userdir /srv/pyload/u --storagedir /srv/pyload/s \
        --tempdir /srv/pyload/t >/tmp/configure.log 2>&1 || true) \
    && test -f /srv/pyload/u/settings/pyload.cfg
COPY fix_config.py /tmp/fix_config.py
RUN python /tmp/fix_config.py \
    && rm /tmp/fix_config.py \
    && chown -R pyload:pyload /srv/pyload \
    && rm -rf /tmp/pyLoad

COPY proof.c /tmp/proof.c
RUN gcc -O2 -Wall -Wextra -Werror -o /usr/local/bin/pyload-proof /tmp/proof.c \
    && chown root:root /usr/local/bin/pyload-proof \
    && chmod 4555 /usr/local/bin/pyload-proof \
    && rm /tmp/proof.c \
    && install -d -o root -g root -m 0700 /var/lib/pyload-arena \
    && install -d -o root -g pyload -m 0710 /var/lib/pyload-arena/proofs

COPY facility.py /arena/facility.py
COPY restart.sh /arena/restart.sh
COPY entrypoint.sh /arena/entrypoint.sh
RUN chmod 0555 /arena/facility.py /arena/restart.sh /arena/entrypoint.sh \
    && chown root:root /arena/facility.py /arena/restart.sh /arena/entrypoint.sh \
    && mkdir -p /run/sshd /home/arena_agent/.ssh \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 8000 22
CMD ["/arena/entrypoint.sh"]
