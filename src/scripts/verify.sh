#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
build_dir=${PROBE_BUILD_DIR:-"$repo_dir/.local/build"}
mkdir -p "$build_dir"
python3 "$repo_dir/src/scripts/check_shared.py"
cmake -S "$repo_dir" -B "$build_dir" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS_DEBUG='-O0 -g0' -DBUILD_TESTING=ON > "$build_dir/configure.log" 2>&1
cmake --build "$build_dir" -j "${PROBE_BUILD_JOBS:-2}" > "$build_dir/build.log" 2>&1
ctest --test-dir "$build_dir" --output-on-failure \
    --output-junit "$build_dir/ctest.xml" | tee "$build_dir/ctest.log"
