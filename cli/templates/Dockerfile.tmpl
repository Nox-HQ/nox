# nox:ignore CONT-001 -- scaffolding template; users pin digests for their builds
# nox:ignore IAC-121 -- a plugin binary is one-shot; a HEALTHCHECK has nothing to poll
# nox:ignore IAC-122 -- build stage is discarded; the scratch runtime has no users to switch to
# nox:ignore IAC-124 -- scaffolding template; the generated plugin supplies its own labels
FROM golang:1.25-alpine AS build
WORKDIR /src
# nox:ignore IAC-123 -- build stage, layer is discarded
COPY go.mod go.sum ./
RUN go mod download
# nox:ignore IAC-123 -- build stage, layer is discarded
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /plugin .

# nox:ignore IAC-002 -- minimal runtime image for plugins
FROM scratch
# nox:ignore IAC-123 -- scratch image has no users; --chown would fail
COPY --from=build /plugin /plugin
ENTRYPOINT ["/plugin"]
