FROM golang:1.24-alpine AS builder
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build \
    -ldflags="-s -w -X github.com/outscale-srt20/osc-policy/version.Version=${VERSION}" \
    -o osc-policy .

FROM alpine:3.21
ARG VERSION=dev
LABEL org.opencontainers.image.title="osc-policy" \
      org.opencontainers.image.description="Policy-as-code scanner for Outscale (security, FinOps, compliance)" \
      org.opencontainers.image.source="https://github.com/outscale-srt20/osc-policy" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"
RUN apk add --no-cache ca-certificates \
 && adduser -D -H -s /sbin/nologin osc-policy
COPY --from=builder /app/osc-policy /usr/local/bin/
USER osc-policy
ENTRYPOINT ["osc-policy"]
