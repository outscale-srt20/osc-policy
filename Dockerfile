FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS builder
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build \
    -ldflags="-s -w -X github.com/outscale-srt20/osc-policy/version.Version=${VERSION}" \
    -o osc-policy .

FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
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
