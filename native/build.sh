#!/usr/bin/env bash
# Basilisk Native Extensions — Build Script v1.0.8
#
# Compiles Go and C native performance modules into shared libraries
# that Python loads via ctypes for 10-100x speedup on hot paths.
#
# Usage: ./build.sh [all|go|c|clean|verify|info]
#
# Modules:
#   C  → libbasilisk_tokens (token estimation, entropy, similarity, confusables)
#   C  → libbasilisk_encoder (base64, hex, ROT13, URL, Unicode escapes)
#   Go → libbasilisk_fuzzer  (15 mutation operators, crossover, batch ops)
#   Go → libbasilisk_matcher (Aho-Corasick, refusal/compliance/sensitive detection)
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

    # Fetch dependencies
    log_info "  → Fetching Go dependencies..."
    go mod tidy 2>/dev/null || true
    go mod download 2>/dev/null || true

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
    rm -f "${LIB_DIR}"/*.so "${LIB_DIR}"/*.dylib "${LIB_DIR}"/*.dll "${LIB_DIR}"/*.h
    log_info "Clean complete"
}

verify() {
    log_info "Verifying native extensions..."
    local all_ok=true

    # Check C libraries
    for lib in libbasilisk_tokens libbasilisk_encoder; do
        local path="${LIB_DIR}/${lib}${SO_EXT}"
        if [ -f "${path}" ]; then
            local size=$(stat -c%s "${path}" 2>/dev/null || stat -f%z "${path}" 2>/dev/null)
            log_info "  ✓ ${lib} (${size} bytes)"
        else
            log_error "  ✗ ${lib} — NOT FOUND"
            all_ok=false
        fi
    done

    # Check Go libraries
    for lib in libbasilisk_fuzzer libbasilisk_matcher; do
        local path="${LIB_DIR}/${lib}${SO_EXT}"
        if [ -f "${path}" ]; then
            local size=$(stat -c%s "${path}" 2>/dev/null || stat -f%z "${path}" 2>/dev/null)
            # Verify exported symbols
            local exports=$(nm -D "${path}" 2>/dev/null | grep -c ' T ' || echo 0)
            log_info "  ✓ ${lib} (${size} bytes, ${exports} exports)"
        else
            log_error "  ✗ ${lib} — NOT FOUND"
            all_ok=false
        fi
    done

    # Check key symbols in fuzzer
    local fuzzer_path="${LIB_DIR}/libbasilisk_fuzzer${SO_EXT}"
    if [ -f "${fuzzer_path}" ]; then
        for sym in BasiliskMutate BasiliskCrossover BasiliskBatchMutate BasiliskPopulationDiversity BasiliskGetMutationCount; do
            if nm -D "${fuzzer_path}" 2>/dev/null | grep -q "${sym}"; then
                log_info "    └─ ${sym}: ✓"
            else
                log_warn "    └─ ${sym}: MISSING"
            fi
        done
    fi

    # Check key symbols in matcher
    local matcher_path="${LIB_DIR}/libbasilisk_matcher${SO_EXT}"
    if [ -f "${matcher_path}" ]; then
        for sym in BasiliskDetectRefusal BasiliskDetectCompliance BasiliskDetectSensitiveData BasiliskMatcherSearch; do
            if nm -D "${matcher_path}" 2>/dev/null | grep -q "${sym}"; then
                log_info "    └─ ${sym}: ✓"
            else
                log_warn "    └─ ${sym}: MISSING"
            fi
        done
    fi

    if ${all_ok}; then
        log_info "All native extensions verified ✓"
    else
        log_error "Some extensions are missing — run ./build.sh all"
        exit 1
    fi
}

show_info() {
    echo "Basilisk Native Extensions v1.0.8"
    echo ""
    echo "Platform:  ${OS}/${ARCH}"
    echo "Extension: ${SO_EXT}"
    echo "Build Dir: ${BUILD_DIR}"
    echo "Lib Dir:   ${LIB_DIR}"
    echo ""
    echo "Modules:"
    echo "  C  │ tokens  → token estimation, entropy, Levenshtein, confusables, BMH search"
    echo "  C  │ encoder → base64, hex, ROT13, URL encode, Unicode escape, reverse"
    echo "  Go │ fuzzer  → 15 mutation operators (11 base + 4 multi-turn), 3 crossover modes,"
    echo "     │           batch mutation, population diversity scoring"
    echo "  Go │ matcher → Aho-Corasick multi-pattern, refusal detection (40 patterns),"
    echo "     │           compliance detection (20 patterns), sensitive data (27 patterns)"
    echo ""
    echo "Go:    $(go version 2>/dev/null || echo 'not installed')"
    echo "CC:    $(${CC:-gcc} --version 2>/dev/null | head -1 || echo 'not installed')"
}

show_help() {
    echo "Basilisk Native Extensions Build System v1.0.8"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all      Build all native extensions (default)"
    echo "  go       Build Go extensions only"
    echo "  c        Build C extensions only"
    echo "  clean    Remove build artifacts"
    echo "  verify   Verify built libraries and exported symbols"
    echo "  info     Show build configuration and module details"
    echo "  help     Show this help"
    echo ""
    echo "Environment:"
    echo "  CC       C compiler (default: gcc)"
    echo ""
    echo "Examples:"
    echo "  ./build.sh all      # Build everything"
    echo "  ./build.sh verify   # Check built libraries"
    echo "  ./build.sh clean    # Remove all artifacts"
}

# Main dispatch
case "${1:-all}" in
    all)
        build_c
        build_go
        log_info "All native extensions built → ${LIB_DIR}/"
        ls -la "${LIB_DIR}/"
        echo ""
        verify
        ;;
    c)      build_c ;;
    go)     build_go ;;
    clean)  clean ;;
    verify) verify ;;
    info)   show_info ;;
    help|-h|--help) show_help ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
