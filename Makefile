VERSION ?= 0.0.1-dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/marstack-labs/marstack-access/internal/version.Version=$(VERSION) \
           -X github.com/marstack-labs/marstack-access/internal/version.Commit=$(COMMIT)

GOBIN  ?= $(shell go env GOPATH)/bin
PREFIX ?= /usr/local

.PHONY: build install uninstall test vet fmt staticcheck vuln gosec secrets security check tools hooks run clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/marac ./cmd/marac

install:
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 bin/marac $(DESTDIR)$(PREFIX)/bin/marac

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/marac

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
	rm -rf bin data coverage.out
