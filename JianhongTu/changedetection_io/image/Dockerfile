FROM --platform=linux/amd64 python:3.11.15-slim-bookworm@sha256:77923445c077d8eb971b14b2b114a1d9cd4a87edb4c75654820ca4832ee8cb15 AS build

ARG SOURCE_SHA256=1ee28dcf40c51857e1ab8ee07839d5512f0cdcb119f4aa25f8d58c966aaa4ba2
COPY source-primary.tar.gz /tmp/source-primary.tar.gz
RUN echo "${SOURCE_SHA256}  /tmp/source-primary.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/challenge_src/changedetection \
    && tar -xzf /tmp/source-primary.tar.gz --strip-components=1 \
        -C /opt/challenge_src/changedetection \
    && grep -qF 'from elementpath.xpath3 import XPath3Parser' \
        /opt/challenge_src/changedetection/changedetectionio/html_tools.py \
    && ! grep -qF 'SafeXPath3Parser' \
        /opt/challenge_src/changedetection/changedetectionio/html_tools.py

COPY requirements.lock /requirements.lock
RUN pip install --no-cache-dir --prefer-binary --no-deps \
        --target=/dependencies -r /requirements.lock \
    && PYTHONPATH=/dependencies /dependencies/bin/pybabel compile \
        -d /opt/challenge_src/changedetection/changedetectionio/translations

FROM --platform=linux/amd64 python:3.11.15-slim-bookworm@sha256:77923445c077d8eb971b14b2b114a1d9cd4a87edb4c75654820ca4832ee8cb15

ARG DEBIAN_SNAPSHOT=20260715T000000Z
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH=/usr/local \
    PYTHONUNBUFFERED=1 \
    LC_ALL=C.UTF-8 \
    FETCH_WORKERS=4 \
    MINIMUM_SECONDS_RECHECK_TIME=0 \
    DISABLE_VERSION_CHECK=true \
    ALLOW_IANA_RESTRICTED_ADDRESSES=true

RUN rm -f /etc/apt/sources.list.d/* \
    && printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s bookworm main\ndeb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/%s bookworm-security main\n' \
        "${DEBIAN_SNAPSHOT}" "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server git procps curl file locales poppler-utils \
        libxslt1.1 zlib1g libglib2.0-0 libsm6 libxext6 libxrender1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home --shell /bin/bash arena_agent \
    && mkdir -p /run/sshd /home/arena_agent/.ssh /arena /datastore \
        /opt/challenge_src /srv/challenge /var/lib/changedetection \
    && chown arena_agent:arena_agent /home/arena_agent/.ssh /datastore \
        /var/lib/changedetection \
    && chmod 0700 /home/arena_agent/.ssh \
    && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY --from=build /dependencies /usr/local
COPY --from=build /opt/challenge_src/changedetection /opt/challenge_src/changedetection
RUN chmod -R a+rX /opt/challenge_src/changedetection

COPY entrypoint.sh start.sh restart.sh facility.py /arena/
RUN chmod 0755 /arena/entrypoint.sh /arena/start.sh /arena/restart.sh \
    && chmod 0700 /arena/facility.py \
    && chown -R root:root /arena

EXPOSE 5000 22
ENTRYPOINT ["/arena/entrypoint.sh"]
