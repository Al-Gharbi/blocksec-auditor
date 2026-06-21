BINARY=blocksec-auditor
LDFLAGS=-s -w

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/auditor

test:
	go test -v -race ./...

lint:
	golangci-lint run

clean:
	rm -f $(BINARY)
