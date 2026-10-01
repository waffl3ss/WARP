BIN      := bin
PKG      := github.com/waffl3ss/warp
# The version lives in internal/build, not here: a plain `go build` must produce a binary that
# knows what it is. The Makefile only adds the commit, which source alone cannot know.
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null)
DIRTY    := $(shell git diff --quiet 2>/dev/null || echo +dirty)
LDFLAGS  := -s -w -X $(PKG)/internal/build.Commit=$(COMMIT)$(DIRTY)

# CGO_ENABLED=0 throughout: WARP ships as a single static binary that runs on whatever is in
# the client's closet, without matching a glibc version.
GO       := CGO_ENABLED=0 go

.PHONY: all build cross test race lint fmt vet check scope-audit clean install

all: check build

build:
	@mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/warp  ./cmd/warp
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/warpd ./cmd/warpd

# Engagement hardware is a mix of amd64 laptops and arm64 NUCs/SBCs.
cross:
	@mkdir -p $(BIN)
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/warp-linux-amd64  ./cmd/warp
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/warp-linux-arm64  ./cmd/warp
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/warpd-linux-amd64 ./cmd/warpd
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/warpd-linux-arm64 ./cmd/warpd

test:
	$(GO) test ./...

race:
	go test -race ./...

fmt:
	gofmt -l -w .

vet:
	$(GO) vet ./...

lint:
	@out=$$(gofmt -l . | grep -v '^$$' || true); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...

# The scope gate is what keeps WARP inside the Statement of Work. These assertions run
# repo-wide over the AST, so they also cover modules added after they were written.
scope-audit:
	$(GO) test ./internal/scope/ -run 'TestNo|TestEveryTransmitting|TestRogueAP|TestAuthorizationSucceeds|TestAuditScanner' -v

check: lint test scope-audit

install: build
	install -m 0755 $(BIN)/warp  /usr/local/bin/warp
	install -m 0755 $(BIN)/warpd /usr/local/bin/warpd

clean:
	rm -rf $(BIN)
