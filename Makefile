GO ?= go
DIST_DIR := $(CURDIR)/dist
SERVER_AMD64 := $(DIST_DIR)/codboz-online-server.linux-amd64
SERVER_ARM64 := $(DIST_DIR)/codboz-online-server.linux-arm64
GO_FILES := $(shell find . -type f -name '*.go' -not -path './.git/*' -not -path './vendor/*')

.PHONY: build-linux build-linux-amd64 build-linux-arm64 check clean fmt fmt-check lint test test-race tidy tidy-check

check: fmt-check tidy-check lint test-race

build-linux: build-linux-amd64 build-linux-arm64

build-linux-amd64:
	mkdir -p "$(DIST_DIR)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' \
		-o "$(SERVER_AMD64)" ./cmd/codboz-online-server

build-linux-arm64:
	mkdir -p "$(DIST_DIR)"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		$(GO) build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' \
		-o "$(SERVER_ARM64)" ./cmd/codboz-online-server

clean:
	rm -rf "$(DIST_DIR)"

fmt:
	gofmt -w $(GO_FILES)

fmt-check:
	@test -z "$$(gofmt -l $(GO_FILES))" || { \
		printf 'Run make fmt; these files are not formatted:\n%s\n' "$$(gofmt -l $(GO_FILES))"; \
		exit 1; \
	}

lint:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

tidy:
	$(GO) mod tidy

tidy-check:
	$(GO) mod tidy -diff
