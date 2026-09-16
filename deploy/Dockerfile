FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/ip ./cmd/ip && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/ip-probe ./cmd/probe

FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/ip" \
      org.opencontainers.image.description="Placitum ip inspector: address, network and ASN decisions, live lists" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-ip" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/ip /out/ip-probe /usr/local/bin/
COPY policy ./policy
COPY inspector.conf ./inspector.conf

RUN mkdir -p /app/data/geo && \
    adduser -D -H -u 10001 ip && \
    chown -R ip:ip /app
USER ip

ENV NATS_URL=nats://nats:4222 \
    WAF_IP_SUBJECT=waf.req.ip \
    WAF_IP_NAME=ip \
    WAF_IP_POLICY=/app/policy \
    WAF_IP_GEO=/app/data/geo \
    WAF_IP_DATA=/app/state \
    WAF_IP_LOG=info

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["ip-probe", "--quiet", "--timeout", "1s", "--client-ip", "127.0.0.1"]

CMD ["ip"]
