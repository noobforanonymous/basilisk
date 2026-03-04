---
description: How to build and test the Basilisk project
---

This workflow uses the standardized `Makefile` to build native extensions and run the test suite.

// turbo
1. Build native extensions:
   ```bash
   make build-native
   ```

// turbo
2. Run the test suite:
   ```bash
   make test
   ```

// turbo
3. Build the desktop backend (PyInstaller):
   ```bash
   make build-backend
   ```
   *Note: This requires `pyinstaller` to be installed in your virtual environment.*

// turbo
4. Start the desktop application in development mode:
   ```bash
   make dev
   ```

5. Clean build artifacts:
   ```bash
   make clean
   ```
