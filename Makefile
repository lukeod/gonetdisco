.PHONY: build test test-short clean lint run help coverage

# Binary name
BINARY=gonetdisco
VERSION=$(shell git describe --tags --always --abbrev=0 || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD || echo "unknown")
BUILD_DATE=$(shell date +%FT%T%z)

# Build directory
BUILD_DIR=build

# Linker flags
LDFLAGS=-ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}"

help:
	@echo "GoNetDisco Makefile"
	@echo "Available commands:"
	@echo "  make build       - Build the binary"
	@echo "  make run         - Build and run the binary"
	@echo "  make test        - Run all tests"
	@echo "  make test-short  - Run short tests only (no network tests)"
	@echo "  make lint        - Run linters"
	@echo "  make coverage    - Generate test coverage report"
	@echo "  make clean       - Remove build artifacts"

build:
	@echo "Building ${BINARY}..."
	@mkdir -p ${BUILD_DIR}
	@go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY} .

run: build
	@echo "Running ${BINARY}..."
	@./${BUILD_DIR}/${BINARY}

test:
	@echo "Running all tests..."
	@go test -v ./...

test-short:
	@echo "Running short tests only..."
	@go test -v -short ./...

coverage:
	@echo "Generating test coverage report..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint:
	@echo "Running linters..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Installing..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		golangci-lint run ./...; \
	fi

clean:
	@echo "Cleaning up..."
	@rm -rf ${BUILD_DIR}
	@rm -f coverage.out coverage.html
	@go clean