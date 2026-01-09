.PHONY: help lint build test test-verbose test-coverage test-coverage-html test-clean install-pre-push-hook uninstall-pre-push-hook

help:
	@echo "Available commands:"
	@echo "  help                         - Show this help message"
	@echo "  lint                         - Run golangci-lint on the codebase"
	@echo "  build                        - Build the project"
	@echo "  test                     	  - Run all tests"
	@echo "  test-verbose                 - Run all tests with verbose output"
	@echo "  test-coverage                - Run tests with coverage report for each package"
	@echo "  test-coverage-html           - Run tests and generate HTML coverage reports for each package"
	@echo "  test-clean                   - Clean test cache and run tests"
	@echo "  install-pre-push-hook        - Install the pre-push git hook"
	@echo "  uninstall-pre-push-hook      - Uninstall the pre-push git hook"
	@echo "  mock                         - Generate mocks"

lint:
	golangci-lint run ./...

build:
	go build -v ./...

test:
	@echo "Running all tests..."
	go test ./...

test-verbose:
	@echo "Running all tests with verbose output..."
	go test -v ./...

test-coverage:
	@echo "Running tests with coverage report for each package..."
	@for pkg in $$(go list ./...); do \
		pkgname=$$(echo $$pkg | tr '/' '-'); \
		echo "Coverage for $$pkg:"; \
		go test -v -coverpkg=$$pkg -coverprofile=coverage-$$pkgname.out $$pkg; \
	done

test-coverage-html:
	@echo "Running tests and generating HTML coverage reports for each package..."
	@for pkg in $$(go list ./...); do \
		pkgname=$$(echo $$pkg | tr '/' '-'); \
		echo "Coverage for $$pkg:"; \
		go test -v -coverpkg=$$pkg -coverprofile=coverage-$$pkgname.out $$pkg; \
		go tool cover -html=coverage-$$pkgname.out -o coverage-$$pkgname.html; \
	done
	@echo "Coverage reports generated: coverage-*.html"

test-clean:
	@echo "Cleaning test cache and running tests..."
	go clean -testcache && go test -v ./...

install-pre-push-hook:
	@echo "Installing pre-push git hook..."
	@mkdir -p .git/hooks
	@cp scripts/git-pre-push.sh .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "Pre-push hook installed successfully!"

uninstall-pre-push-hook:
	@echo "Uninstalling pre-push git hook..."
	@rm -f .git/hooks/pre-push
	@echo "Pre-push hook uninstalled successfully!"
