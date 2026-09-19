# Build stage
# nox:ignore IAC-121 -- nox is a one-shot CLI; a HEALTHCHECK has nothing to poll
# nox:ignore IAC-124 -- maintainer is carried by the OCI labels on the runtime stage
FROM golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS builder

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
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

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
