# syntax=docker/dockerfile:1.7
FROM apache/apisix:3.13.0-debian AS apisix
USER root
RUN echo "PATH=/usr/local/bin:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin" >> /.buildvars-apisix

FROM ubuntu:noble AS root
ARG DEBIAN_FRONTEND=noninteractive
RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=tmpfs,target=/var/lib/apt/lists/ \
    --mount=type=tmpfs,target=/tmp \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        supervisor inetutils-ping telnet git curl \
        etcd-server etcd-client \
        libldap2-dev libyaml-0-2 brotli libpcre2-8-0 \
        libpcre3-dev libpcre3 \
        libssl3 libgeoip1 libxslt1.1 \ 
        ca-certificates build-essential make gcc g++ python3 dnsutils nano && \
        update-ca-certificates

FROM root AS hydra-downloader
ARG HYDRA_VERSION=2.3.0
COPY ./conf/etc/hydra/config.yaml /etc/hydra/config.yaml
RUN --mount=type=tmpfs,target=/tmp \
    curl -L -o /tmp/hydra.tar.gz \
    "https://github.com/ory/hydra/releases/download/v${HYDRA_VERSION}/hydra_${HYDRA_VERSION}-linux_sqlite_64bit.tar.gz" && \
    tar -xzf /tmp/hydra.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/hydra && \
    mkdir -p /hydra-data && \
    touch /hydra-data/hydra.sqlite && \
    hydra migrate sql up -y -c /etc/hydra/config.yaml -e
    
FROM root AS nodejs-builder
WORKDIR /node-apps
COPY ./app/package*.json ./
RUN export NVM_DIR="/nvm" && \
    mkdir /nvm -p && \
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash && \
    . /nvm/nvm.sh && \
    nvm install 24 && \
    nvm use 24 && \
    npm install -g npm && \
    npm install -g js-yaml && \
    npm install --production && \
    echo "PATH=/nvm/versions/node/$(node --version)/bin" >> /.buildvars-nodejs-builder && \
    echo "NODE_PATH=/nvm/versions/node/$(node --version)/lib/node_modules" >> /.buildvars-nodejs-builder

COPY ./app/config ./config
COPY ./app/public ./public
COPY ./app/templates ./templates
COPY ./app/mcp-*.js ./
COPY ./static /static

FROM root AS base
COPY --from=hydra-downloader /usr/local/bin/hydra /usr/bin/hydra
COPY --from=hydra-downloader /hydra-data /hydra-data
COPY --from=apisix /usr/local/apisix /usr/local/apisix
COPY --from=apisix /usr/local/openresty /usr/local/openresty
COPY --from=apisix /usr/bin/apisix /usr/bin/apisix
COPY --from=apisix /.buildvars-apisix /.buildvars-apisix
COPY --from=nodejs-builder /nvm /nvm
COPY --from=nodejs-builder /node-apps /node-apps
COPY --from=nodejs-builder /.buildvars-nodejs-builder /.buildvars-nodejs-builder 
COPY --from=nodejs-builder /static /static
COPY ./conf/ /

# Setup folders and symlinks, collect all data which should be copied to volumes on runtime and apply nmp env vars
RUN mkdir -p /usr/local/apisix/ui /usr/local/apisix/logs /etcd-data && \
    touch /usr/local/apisix/logs/access.log && \
    touch /usr/local/apisix/logs/error.log && \
    ln -sf /dev/stdout /usr/local/apisix/logs/access.log && \
    ln -sf /dev/stderr /usr/local/apisix/logs/error.log && \
    chmod +x /scripts/*.sh && \
    mkdir -p /init_data/etcd-data && \
    mkdir -p /init_data/hydra-data && \ 
    cp -a /etcd-data /init_data/ && \
    cp -a /hydra-data /init_data/ && \
    echo "export PATH=$PATH:$(. /.buildvars-apisix && echo $PATH):$(. /.buildvars-nodejs-builder && echo $PATH)" >> /.buildvars && \
    echo "export NODE_PATH=$(. /.buildvars-nodejs-builder && echo $NODE_PATH)" >> /.buildvars && \
    echo "source /.buildvars" >> /etc/bash.bashrc && \
    rm /.buildvars-nodejs-builder /.buildvars-apisix

# APISIX Ports    
#9080: This port handles incoming HTTP requests from clients to the API gateway.
#9443: This port handles incoming HTTPS requests with SSL enabled.
#9180: This port is used by the Admin API for managing and configuring APISIX.
EXPOSE 9080 9443 9180

CMD ["/scripts/docker-start.sh"]