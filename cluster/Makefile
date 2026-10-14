VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/hitechcloud-vietnam/hitechcloud-waf-cluster

.PHONY: build test image
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/hcw ./cmd/hcw
test:
	go vet ./... && go test -race ./...
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .
