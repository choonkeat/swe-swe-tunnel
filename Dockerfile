FROM golang:1.26.10-alpine AS builder
# git is required for `go build` to populate runtime/debug.ReadBuildInfo
# vcs.revision/vcs.time. Without it, buildvcs=auto silently disables
# and the binary reports version=unknown at boot.
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/swe-swe-tunneld ./cmd/swe-swe-tunneld

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
# Run as an unprivileged user. UID/GID 10001 is fixed so the
# docker-compose.yml volume-perms step can chown existing state to it.
# Binding :443 needs no capability: Docker sets
# net.ipv4.ip_unprivileged_port_start=0 in the container (also pinned
# in docker-compose.yml).
RUN addgroup -S -g 10001 tunnel \
 && adduser -S -D -H -u 10001 -G tunnel -s /sbin/nologin tunnel \
 && mkdir -p /var/lib/swe-swe-tunnel \
 && chown tunnel:tunnel /var/lib/swe-swe-tunnel
COPY --from=builder /out/swe-swe-tunneld /usr/local/bin/swe-swe-tunneld
USER 10001:10001
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/swe-swe-tunneld"]
