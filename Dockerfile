# syntax=docker/dockerfile:1
FROM debian:trixie-slim AS builder

# Install Build Dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates \
    autopoint \
    libtool \
    automake \
    autoconf \
    pkg-config \
    libgd-dev \
    libxslt1-dev \
    libmaxminddb-dev \
    libpam0g-dev \
    libperl-dev \
    libreadline-dev \
    libncurses5-dev \
    libpcre2-dev \
    libssl-dev \
    zlib1g-dev \
    libzstd-dev \
    libxml2-dev \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Copy Build Script
COPY build.sh /build.sh
RUN dos2unix /build.sh && chmod +x /build.sh

# Execute Build
# This script manages versions, downloads, and compilation
ARG NGINX_VERSION
ENV NGINX_VERSION=${NGINX_VERSION}
RUN /bin/bash /build.sh

# Export Stage
# This allows 'docker build --output type=local,dest=.' to extract the tarball
FROM scratch AS export
COPY --from=builder /build/output/nginx-custom.tar.gz /
COPY --from=builder /build/output/expected_modules.txt /
