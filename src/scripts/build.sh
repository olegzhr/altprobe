#!/usr/bin/env bash
#
# Local build helper for the Altprobe collector.
#
#   bash src/scripts/build.sh                 # configure, build and run CTest
#   bash src/scripts/build.sh build           # compile only
#   bash src/scripts/build.sh test            # run CTest only
#   bash src/scripts/build.sh package         # build the .deb package
#   bash src/scripts/build.sh clean           # remove the build directory
#
# Environment:
#   ALTPROBE_BUILD_DIR          build directory (default: <repo>/build)
#   BUILD_JOBS                  parallel jobs (default: number of CPUs)
#   ALTPROBE_CRS_ARCHIVE        local OWASP CRS archive for offline packaging
#   ALTPROBE_CRS_ARCHIVE_SHA256 SHA-256 of that archive
#
# The script never touches the release version: it must stay 1.0.2.
set -euo pipefail

ROOT="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
BUILD_DIR="${ALTPROBE_BUILD_DIR:-$ROOT/build}"
JOBS="${BUILD_JOBS:-$( (getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 2) )}"
BUILD_TYPE=Release
PACKAGE_CRS=ON
JUNIT=""
COMMAND=""

usage() {
    cat <<'EOF'
Usage: bash src/scripts/build.sh [command] [options]

Commands:
  all             configure, build and run CTest (default)
  configure       run CMake only
  build           configure and compile
  test            run CTest
  package         build the altprobe_1.0.2_amd64.deb package
  clean           remove the build directory

Options:
  --build-dir DIR   build directory
  --jobs N          parallel build jobs
  --junit FILE      write CTest results as JUnit XML
  --no-crs          build the package without the bundled OWASP CRS
  --debug           build with CMAKE_BUILD_TYPE=Debug
  -h, --help        show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --junit) JUNIT="$2"; shift 2 ;;
        --no-crs) PACKAGE_CRS=OFF; shift ;;
        --debug) BUILD_TYPE=Debug; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) COMMAND="$1"; shift ;;
    esac
done

case "${COMMAND:-all}" in
    configure|build|test|package|clean|all) ;;
    *) echo "Unknown command: $COMMAND" >&2; usage >&2; exit 2 ;;
esac
COMMAND="${COMMAND:-all}"

for tool in cmake; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Required tool not found: $tool" >&2; exit 1; }
done

if [[ "$BUILD_DIR" == /mnt/* ]]; then
    echo "WARNING: $BUILD_DIR is on a Windows drive under WSL." >&2
    echo "         Linking and archiving there is very slow; use a path under \$HOME." >&2
fi

configure() {
    local crs_args=(-DALTPROBE_PACKAGE_CRS="$PACKAGE_CRS")
    if [[ -n "${ALTPROBE_CRS_ARCHIVE:-}" ]]; then
        crs_args+=(-DALTPROBE_CRS_ARCHIVE="$ALTPROBE_CRS_ARCHIVE")
    fi
    if [[ -n "${ALTPROBE_CRS_ARCHIVE_SHA256:-}" ]]; then
        crs_args+=(-DALTPROBE_CRS_ARCHIVE_SHA256="$ALTPROBE_CRS_ARCHIVE_SHA256")
    fi
    echo "== configure: $BUILD_DIR ($BUILD_TYPE, CRS package: $PACKAGE_CRS)"
    cmake -S "$ROOT" -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DBUILD_TESTING=ON \
        "${crs_args[@]}"
}

build() {
    echo "== build: $JOBS job(s)"
    cmake --build "$BUILD_DIR" --parallel "$JOBS"
    echo "== binary: $BUILD_DIR/src/altprobe"
}

test_suite() {
    if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]]; then
        configure
    fi
    local args=(--test-dir "$BUILD_DIR" --output-on-failure)
    if [[ -n "$JUNIT" ]]; then
        mkdir -p "$(dirname -- "$JUNIT")"
        args+=(--output-junit "$JUNIT")
    fi
    echo "== ctest"
    ctest "${args[@]}"
}

package() {
    echo "== package"
    cmake --build "$BUILD_DIR" --target package
    local deb="$BUILD_DIR/altprobe_1.0.2_amd64.deb"
    [[ -f "$deb" ]] || { echo "Package was not created: $deb" >&2; exit 1; }
    echo "== package: $deb"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$deb"
    fi
}

clean() {
    local target home_path
    if [[ ! -e "$BUILD_DIR" && ! -L "$BUILD_DIR" ]]; then return 0; fi
    target=$(cd -P -- "$BUILD_DIR" && pwd -P) || return 1
    home_path=$(cd -P -- "$HOME" && pwd -P) || return 1
    if [[ -L "$BUILD_DIR" || "$target" == / || "$target" == "$ROOT" ||
          "$ROOT" == "$target/"* || "$target" == "$home_path" || "$home_path" == "$target/"* ]] ||
       [[ ! -f "$target/CMakeCache.txt" ]] ||
       ! grep -Fxq "CMAKE_HOME_DIRECTORY:INTERNAL=$ROOT" "$target/CMakeCache.txt" ||
       ! grep -Fxq "CMAKE_CACHEFILE_DIR:INTERNAL=$target" "$target/CMakeCache.txt"; then
        echo "Refusing to remove '$BUILD_DIR': expected an Altprobe CMake build directory" >&2
        return 1
    fi
    echo "== clean: $target"
    rm -rf -- "$target"
}

case "$COMMAND" in
    configure) configure ;;
    build) configure; build ;;
    test) test_suite ;;
    package) configure; build; package ;;
    clean) clean ;;
    all) configure; build; test_suite ;;
esac
