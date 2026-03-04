# Basilisk Project Makefile
# Unified build system for Python core, Native extensions, and Electron desktop.

PYTHON = python3
PIP = $(PYTHON) -m pip
NATIVE_DIR = native
DESKTOP_DIR = desktop
REPORT_DIR = basilisk-reports

all: build-native build-backend  ## Build everything (native extensions + backend binary)

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install all dependencies (Python + Desktop)
	@echo "Installing Python dependencies..."
	$(PIP) install -r requirements.txt
	@echo "Installing Desktop dependencies..."
	cd $(DESKTOP_DIR) && npm install

build: build-native ## Build all components

build-native: ## Compile Go and C extensions
	@echo "Building native extensions..."
	./$(NATIVE_DIR)/build.sh all

build-backend: build-native ## Build the standalone Python backend binary (PyInstaller)
	@echo "Building standalone backend binary..."
	$(PYTHON) -m PyInstaller basilisk-backend.spec

build-desktop: install ## Build the Electron application (dist)
	@echo "Building desktop application..."
	./build-desktop.sh

dev: build-native ## Run the desktop application in development mode
	@echo "Starting desktop application in dev mode..."
	cd $(DESKTOP_DIR) && npm start

test: build-native ## Run all tests (requires built native extensions)
	@echo "Running test suite..."
	$(PYTHON) -m pytest tests/

lint: ## Run linting checks
	@echo "Running Ruff/Flake8 check..."
	ruff check . || true
	@echo "Running Go lint..."
	cd $(NATIVE_DIR)/go && go vet ./...

clean: ## Remove build artifacts and temporary files
	@echo "Cleaning native artifacts..."
	./$(NATIVE_DIR)/build.sh clean
	@echo "Cleaning Python artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache
	@echo "Cleaning reports..."
	rm -rf $(REPORT_DIR)
	@echo "Cleaning desktop artifacts..."
	rm -rf $(DESKTOP_DIR)/dist $(DESKTOP_DIR)/node_modules
