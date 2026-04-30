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
    linux-headers

RUN pip3 install --no-cache-dir \
    requests>=2.28.0 \
    httpx>=0.24.0 \
    pyyaml>=6.0 \
    beautifulsoup4>=4.12.0 \
    lxml>=4.9.0

RUN mkdir -p /sandbox/workspace && chmod 777 /sandbox/workspace

WORKDIR /sandbox/workspace

RUN adduser -D -s /bin/sh sandbox && chown -R sandbox:sandbox /sandbox

USER sandbox

ENTRYPOINT []
