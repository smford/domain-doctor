.PHONY: all build test coverage lint clean run

BINARY_NAME := domain-doctor

all: build

build:
	CGO_ENABLED=0 go build -v -ldflags="-s -w" -o $(BINARY_NAME) ./cmd/domain-doctor

test:
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...

coverage: test
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated at coverage.html"

lint:
	pre-commit run --all-files

clean:
	rm -f $(BINARY_NAME) coverage.out coverage.html

run: build
	./$(BINARY_NAME) --help
