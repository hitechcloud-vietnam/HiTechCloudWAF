# HiTechCloud WAF engine
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/hcw-waf ./cmd/hcw-waf

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata libcap \
 && adduser -D -H -u 10002 hcwwaf && install -d -o hcwwaf -m 700 /var/lib/hcw-waf
COPY --from=build /out/hcw-waf /usr/local/bin/hcw-waf
# Bind 80/443 without running as root.
RUN setcap cap_net_bind_service=+ep /usr/local/bin/hcw-waf
LABEL org.opencontainers.image.title="HiTechCloud WAF" \
      org.opencontainers.image.vendor="Pho Tue SoftWare Solutions JSC / HiTechCloud-VN" \
      org.opencontainers.image.licenses="GPL-3.0-only"
USER hcwwaf
ENTRYPOINT ["/usr/local/bin/hcw-waf"]
CMD ["-config", "/etc/hcw-waf/waf.yaml"]
