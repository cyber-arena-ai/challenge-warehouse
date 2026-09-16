FROM golang:1.26-alpine3.23@sha256:33ce311e5eecedee48ec1b84419c1306e9fbd71009f0d5c3f2a6904b579c1ecc AS build

COPY apks/ /tmp/apks/
RUN cd /tmp/apks \
 && sha256sum -c SHA256SUMS \
 && apk add --no-cache --no-network \
      ./bash-5.3.3-r1.apk \
      ./libncursesw-6.5_p20251123-r0.apk \
      ./ncurses-terminfo-base-6.5_p20251123-r0.apk \
      ./readline-8.3.1-r0.apk \
 && rm -rf /tmp/apks
COPY source-primary.tar.gz /tmp/source-primary.tar.gz
RUN echo "e82575405bff98bc240621ed747fd4854329d1740b6a2bde674f392207e2613a  /tmp/source-primary.tar.gz" | sha256sum -c - \
 && mkdir -p /src \
 && tar -xzf /tmp/source-primary.tar.gz -C /src \
 && rm /tmp/source-primary.tar.gz
WORKDIR /src/etcd
RUN grep -qF 'func checkTxnReqsPermission' etcdserver/apply_auth.go \
 && ! sed -n '/func checkTxnReqsPermission/,/^}/p' etcdserver/apply_auth.go \
      | grep -qF 'RequestOp_RequestTxn' \
 && go mod download
RUN --network=none ./build

FROM golang:1.26-alpine3.23@sha256:33ce311e5eecedee48ec1b84419c1306e9fbd71009f0d5c3f2a6904b579c1ecc

COPY apks/ /tmp/apks/
RUN cd /tmp/apks \
 && sha256sum -c SHA256SUMS \
 && apk add --no-cache --no-network ./*.apk \
 && rm -rf /tmp/apks \
 && adduser -D -s /bin/bash arena_agent \
 && mkdir -p /run/sshd /home/arena_agent/.ssh /arena \
      /opt/challenge_src/etcd /srv/challenge /srv/etcd/bin \
      /srv/etcd/data /srv/etcd/private \
 && chown arena_agent:arena_agent /home/arena_agent/.ssh \
 && chmod 0700 /home/arena_agent/.ssh /srv/etcd/private \
 && sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY --from=build /src/etcd /opt/challenge_src/etcd
COPY --from=build /src/etcd/bin/etcd /opt/etcd-bin
COPY --from=build /src/etcd/bin/etcdctl /usr/local/bin/etcdctl
COPY --from=build /go/pkg/mod /go/pkg/mod
RUN chmod -R a+rX /opt/challenge_src/etcd /go/pkg/mod \
 && chmod 0755 /opt/etcd-bin /usr/local/bin/etcdctl

COPY entrypoint.sh start.sh restart.sh /arena/
RUN chmod 0755 /arena/entrypoint.sh /arena/start.sh /arena/restart.sh \
 && chown -R root:root /arena

EXPOSE 22 2379
ENTRYPOINT ["/arena/entrypoint.sh"]
