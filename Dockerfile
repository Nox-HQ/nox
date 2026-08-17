# Build stage
# nox:ignore IAC-121 -- nox is a one-shot CLI; a HEALTHCHECK has nothing to poll
# nox:ignore IAC-124 -- maintainer is carried by the OCI labels on the runtime stage
FROM golang:1.26-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /build

# nox:ignore IAC-123 -- builder stage, layer is discarded
COPY go.mod go.sum ./
RUN go mod download

# nox:ignore IAC-123 -- builder stage, layer is discarded
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o nox ./cli

# Runtime stage — distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

LABEL org.opencontainers.image.title="nox" \
      org.opencontainers.image.description="Language-agnostic security scanner with first-class AI application security" \
      org.opencontainers.image.source="https://github.com/nox-hq/nox" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="nox-hq"

COPY --from=builder --chown=nonroot:nonroot /build/nox /usr/local/bin/nox

# Run as non-root user (65534 = nobody in distroless)
USER nonroot:nonroot

WORKDIR /workspace

ENTRYPOINT ["nox"]
