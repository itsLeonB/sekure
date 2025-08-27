.PHONY: help lint test test-verbose test-coverage test-coverage-html test-clean

help:
	@echo "Available commands:"
	@echo "  help               - Show this help message"
	@echo "  lint               - Run golangci-lint on the codebase"
	@echo "  test               - Run all tests"
	@echo "  test-verbose       - Run all tests with verbose output"
	@echo "  test-coverage      - Run all tests with coverage report"
	@echo "  test-coverage-html - Run all tests and generate HTML coverage report"
	@echo "  test-clean         - Clean test cache and run tests"

lint:
	golangci-lint run ./...

test:
	@echo "Running all tests..."
	go test ./test/...

test-verbose:
	@echo "Running all tests with verbose output..."
	go test -v ./test/...

test-coverage:
	@echo "Running all tests with coverage report..."
	go test -v -cover -coverprofile=coverage.out -coverpkg=./... ./test/...

test-coverage-html:
	@echo "Running all tests and generating HTML coverage report..."
	go test -v -cover -coverprofile=coverage.out -coverpkg=./... ./test/...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-clean:
	@echo "Cleaning test cache and running tests..."
	go clean -testcache && go test -v ./test/...
