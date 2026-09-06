VERSION ?= 0.0.1-dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/marstack-labs/marstack-access/internal/version.Version=$(VERSION) \
           -X github.com/marstack-labs/marstack-access/internal/version.Commit=$(COMMIT)

GOBIN  ?= $(shell go env GOPATH)/bin
PREFIX ?= /usr/local

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
SHA256    := $(shell command -v sha256sum >/dev/null 2>&1 && echo "sha256sum" || echo "shasum -a 256")

.PHONY: build install uninstall dist test vet fmt staticcheck vuln gosec secrets security check tools hooks run clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/marac ./cmd/marac

install:
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 bin/marac $(DESTDIR)$(PREFIX)/bin/marac

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/marac

dist:
	rm -rf dist && mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		echo "building marac $(VERSION) for $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags "$(LDFLAGS)" -o dist/marac ./cmd/marac || exit 1; \
		tar -czf dist/marac_$(VERSION)_$${os}_$${arch}.tar.gz -C dist marac \
			-C .. LICENSE README.md || exit 1; \
		rm dist/marac; \
	done
	cd dist && $(SHA256) *.tar.gz > SHA256SUMS

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

staticcheck:
	$(GOBIN)/staticcheck ./...

vuln:
	$(GOBIN)/govulncheck ./...

gosec:
	$(GOBIN)/gosec -quiet -severity medium -confidence medium ./...

secrets:
	$(GOBIN)/gitleaks detect --redact --no-banner --exit-code 1

security: vuln gosec secrets

check: vet test staticcheck security

tools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install github.com/zricethezav/gitleaks/v8@latest

hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit

run: build
	./bin/marac server

clean:
	rm -rf bin dist data coverage.out
