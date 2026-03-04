#!/usr/bin/env bash
# Basilisk Native Extensions — Build Script
#
# Compiles Go and C native performance modules into shared libraries
# that Python loads via ctypes for 10-100x speedup on hot paths.
#
# Usage: ./build.sh [all|go|c|clean]
#
# Requirements:
#   - Go 1.21+
#   - GCC or Clang with -shared/-fPIC support
#   - Linux x86_64 or ARM64

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
LIB_DIR="${SCRIPT_DIR}/../basilisk/native_libs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[BUILD]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Detect platform
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

case "${OS}" in
    linux)  SO_EXT=".so" ;;
    darwin) SO_EXT=".dylib" ;;
    msys*|mingw*|cygwin*|windows*) SO_EXT=".dll" ;;
    *)      SO_EXT=".so" ;;
esac

build_c() {
    log_info "Building C native extensions..."

    CC="${CC:-gcc}"
    CFLAGS="-shared -fPIC -O3 -Wall -Wextra -Werror"

    mkdir -p "${BUILD_DIR}" "${LIB_DIR}"

    # Token analyzer
    log_info "  → libbasilisk_tokens${SO_EXT}"
    ${CC} ${CFLAGS} \
        -o "${BUILD_DIR}/libbasilisk_tokens${SO_EXT}" \
        "${SCRIPT_DIR}/c/tokens.c" \
        -lm

    # Encoder
    log_info "  → libbasilisk_encoder${SO_EXT}"
    ${CC} ${CFLAGS} \
        -o "${BUILD_DIR}/libbasilisk_encoder${SO_EXT}" \
        "${SCRIPT_DIR}/c/encoder.c"

    # Copy to Python-accessible location
    cp "${BUILD_DIR}/libbasilisk_tokens${SO_EXT}" "${LIB_DIR}/"
    cp "${BUILD_DIR}/libbasilisk_encoder${SO_EXT}" "${LIB_DIR}/"

    # Also check for .dll copies if we are on Windows
    if [[ "${SO_EXT}" == ".dll" ]]; then
        # Some systems might not handle .dll as shared libs easily without specific naming
        cp "${BUILD_DIR}/libbasilisk_tokens${SO_EXT}" "${LIB_DIR}/libbasilisk_tokens.dll"
        cp "${BUILD_DIR}/libbasilisk_encoder${SO_EXT}" "${LIB_DIR}/libbasilisk_encoder.dll"
    fi

    log_info "C extensions built successfully"
}

build_go() {
    log_info "Building Go native extensions..."

    mkdir -p "${BUILD_DIR}" "${LIB_DIR}"

    pushd "${SCRIPT_DIR}/go" > /dev/null

    # Fuzzer engine
    log_info "  → libbasilisk_fuzzer${SO_EXT}"
    CGO_ENABLED=1 go build \
        -buildmode=c-shared \
        -o "${BUILD_DIR}/libbasilisk_fuzzer${SO_EXT}" \
        ./fuzzer/

    # Pattern matcher
    log_info "  → libbasilisk_matcher${SO_EXT}"
    CGO_ENABLED=1 go build \
        -buildmode=c-shared \
        -o "${BUILD_DIR}/libbasilisk_matcher${SO_EXT}" \
        ./matcher/

    popd > /dev/null

    # Copy to Python-accessible location
    cp "${BUILD_DIR}/libbasilisk_fuzzer${SO_EXT}" "${LIB_DIR}/"
    cp "${BUILD_DIR}/libbasilisk_matcher${SO_EXT}" "${LIB_DIR}/"

    # Also copy generated headers
    if [ -f "${BUILD_DIR}/libbasilisk_fuzzer.h" ]; then
        cp "${BUILD_DIR}/libbasilisk_fuzzer.h" "${LIB_DIR}/"
    fi
    if [ -f "${BUILD_DIR}/libbasilisk_matcher.h" ]; then
        cp "${BUILD_DIR}/libbasilisk_matcher.h" "${LIB_DIR}/"
    fi

    log_info "Go extensions built successfully"
}

clean() {
    log_info "Cleaning build artifacts..."
    rm -rf "${BUILD_DIR}"
    rm -rf "${LIB_DIR}"/*.so "${LIB_DIR}"/*.dylib "${LIB_DIR}"/*.h
    log_info "Clean complete"
}

show_help() {
    echo "Basilisk Native Extensions Build System"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all     Build all native extensions (default)"
    echo "  go      Build Go extensions only"
    echo "  c       Build C extensions only"
    echo "  clean   Remove build artifacts"
    echo "  help    Show this help"
    echo ""
    echo "Environment:"
    echo "  CC      C compiler (default: gcc)"
}

# Main dispatch
case "${1:-all}" in
    all)
        build_c
        build_go
        log_info "All native extensions built → ${LIB_DIR}/"
        ls -la "${LIB_DIR}/"
        ;;
    c)    build_c ;;
    go)   build_go ;;
    clean) clean ;;
    help|-h|--help) show_help ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
