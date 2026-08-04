FROM alpine:3.18

LABEL maintainer="Co-RedTeam"
LABEL description="Sandbox container for exploit execution"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

RUN apk add --no-cache \
    python3 \
    py3-pip \
    curl \
    wget \
    netcat-openbsd \
    bind-tools \
    iputils \
    procps \
    nmap \
    nmap-scripts \
    openssl \
    openssh-client \
    jq \
    unzip \
    git \
    gcc \
    musl-dev \
    linux-headers \
    python3-dev \
    ca-certificates \
    bash

RUN pip3 install --no-cache-dir \
    requests>=2.28.0 \
    'httpx[http2]>=0.24.0' \
    pyyaml>=6.0 \
    beautifulsoup4>=4.12.0 \
    lxml>=4.9.0 \
    pyjwt>=2.8.0 \
    pycryptodome>=3.19.0 \
    cryptography>=41.0.0 \
    grpcio>=1.65.0 \
    grpcio-reflection>=1.65.0 \
    protobuf>=5.27.0 \
    urllib3>=2.0.0

RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

RUN mkdir -p /sandbox/workspace && chmod 777 /sandbox/workspace

WORKDIR /sandbox/workspace

RUN adduser -D -s /bin/sh sandbox && chown -R sandbox:sandbox /sandbox

USER sandbox

ENTRYPOINT []
