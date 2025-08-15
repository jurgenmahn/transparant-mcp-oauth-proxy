# syntax=docker/dockerfile:1.7

FROM ubuntu:noble AS root
ARG DEBIAN_FRONTEND=noninteractive
RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=tmpfs,target=/var/lib/apt/lists/ \
    --mount=type=tmpfs,target=/tmp \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        supervisor inetutils-ping telnet git curl \
        libldap2-dev libyaml-0-2 brotli libpcre2-8-0 \
        libpcre3-dev libpcre3 \
        libssl3 libgeoip1 libxslt1.1 \ 
        ca-certificates build-essential make gcc g++ python3 python3-pip python3-venv dnsutils nano  redis-server redis-tools xvfb wget rsync && \
        update-ca-certificates && \
        cd /tmp && \
        wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
        apt install -y ./google-chrome-stable_current_amd64.deb

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
    #npm run setup-playwright && \
    echo "PATH=/nvm/versions/node/$(node --version)/bin" >> /.buildvars-nodejs-builder && \
    echo "NODE_PATH=/nvm/versions/node/$(node --version)/lib/node_modules" >> /.buildvars-nodejs-builder

FROM nodejs-builder AS nodejs-app
WORKDIR /node-apps
COPY ./app/config ./config
COPY ./app/templates ./templates
COPY ./app/server.js ./server.js
COPY ./app/services ./services
COPY ./static /static

FROM root as custom-script-installer
COPY ./custom-install-scripts /custom-install-scripts
COPY ./conf/scripts/install-custom-scripts.sh /

# run user defined custom scripts and capture all changes
RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=tmpfs,target=/var/lib/apt/lists/ \
    --mount=type=tmpfs,target=/tmp \
    --mount=type=cache,target=/install-packages,id=mcp-custom-script-installer \
    chmod +x /install-custom-scripts.sh && \
    /install-custom-scripts.sh

FROM root AS base
COPY --from=hydra-downloader /usr/local/bin/hydra /usr/bin/hydra
COPY --from=hydra-downloader /hydra-data /hydra-data
COPY --from=nodejs-builder /nvm /nvm
COPY --from=nodejs-builder /node-apps /node-apps
COPY --from=nodejs-builder /.buildvars-nodejs-builder /.buildvars-nodejs-builder 
COPY --from=nodejs-app /node-apps/server.js /node-apps/server.js
COPY --from=nodejs-app /node-apps/services /node-apps/services
COPY --from=nodejs-app /node-apps/config /node-apps/config
COPY --from=nodejs-app /node-apps/templates /node-apps/templates
COPY --from=nodejs-app /static /static
COPY ./conf/ /

# Setup folders and symlinks, collect all data which should be copied to volumes on runtime and apply npm env vars
RUN chmod +x /scripts/*.sh && \
    mkdir -p /init_data/hydra-data && \ 
    cp -a /hydra-data /init_data/ && \
    echo "export PATH=$PATH:$(. /.buildvars-nodejs-builder && echo $PATH)" >> /.buildvars && \
    echo "export NODE_PATH=$(. /.buildvars-nodejs-builder && echo $NODE_PATH)" >> /.buildvars && \
    echo "source /.buildvars" >> /etc/bash.bashrc && \
    rm /.buildvars-nodejs-builder

# All changes from custom installed scripts
COPY --from=custom-script-installer /install-packages/ /install-packages/
RUN cd /install-packages && for pkg in *.tar.gz; do [ -f "$pkg" ] && echo "Installing $pkg" && tar -xzf "$pkg" -C / && echo "Success: $pkg" || echo "Failed: $pkg"; done

EXPOSE 3000

CMD ["/scripts/docker-start.sh"]