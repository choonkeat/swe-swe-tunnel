FROM golang:1.24-alpine AS builder
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
