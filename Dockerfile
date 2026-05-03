FROM golang:1.24-alpine AS builder
# git is required for `go build` to populate runtime/debug.ReadBuildInfo
# vcs.revision/vcs.time. Without it, buildvcs=auto silently disables
# and the binary reports version=unknown at boot.
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/swe-swe-tunneld ./cmd/swe-swe-tunneld

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/swe-swe-tunneld /usr/local/bin/swe-swe-tunneld
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/swe-swe-tunneld"]
