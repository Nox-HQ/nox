# The build environment for nox's tree-sitter modules (ADR 0006). Every input
# is pinned: the base image by digest, wasi-sdk by SHA-256. build.sh passes
# both from pins.json, so this file names no version of its own.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG WASI_SDK_URL
ARG WASI_SDK_SHA256
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL -o /tmp/wasi-sdk.tar.gz "$WASI_SDK_URL" \
 && echo "$WASI_SDK_SHA256  /tmp/wasi-sdk.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/wasi-sdk && tar -xzf /tmp/wasi-sdk.tar.gz -C /opt/wasi-sdk --strip-components=1 \
 && rm /tmp/wasi-sdk.tar.gz && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 10001 --create-home builder
USER builder
WORKDIR /work
