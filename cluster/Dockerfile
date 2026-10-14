# HiTechCloud WAF cluster: controller / agent / dns in one image.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/hcw ./cmd/hcw

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H -u 10001 hcw && install -d -o hcw -m 700 /var/lib/hcw
COPY --from=build /out/hcw /usr/local/bin/hcw
LABEL org.opencontainers.image.title="HiTechCloud WAF Cluster" \
      org.opencontainers.image.vendor="Pho Tue SoftWare Solutions JSC / HiTechCloud-VN" \
      org.opencontainers.image.licenses="GPL-3.0-only"
USER hcw
ENTRYPOINT ["/usr/local/bin/hcw"]
