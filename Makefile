GO ?= go
BIN ?= bin

.PHONY: test vet build clean

# Single entry point for tests: vet, then race-enabled unit and integration tests.
test:
	$(GO) vet ./...
	$(GO) test -race -count=1 ./...

# Builds every cmd/* binary. Requires the cmd packages to exist.
build:
	mkdir -p $(BIN)
	$(GO) build -o $(BIN)/ ./cmd/...

clean:
	rm -rf $(BIN)
