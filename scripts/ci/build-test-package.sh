#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
VERSION="${ALTPROBE_VERSION:-1.0.2}"
[[ "$VERSION" == 1.0.2 ]] || { echo 'Product version must remain 1.0.2' >&2; exit 1; }
if [[ -z "${SOURCE_DATE_EPOCH:-}" && -e "$ROOT/.git" ]]; then
    export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
fi
BUILD_DIR="${ALTPROBE_BUILD_DIR:-$ROOT/build-ci}"
DIST_DIR="${ALTPROBE_DIST_DIR:-$ROOT/dist}"
JUNIT="${ALTPROBE_JUNIT:-$ROOT/native-tests.xml}"
export ALTPROBE_BUILD_DIR="$BUILD_DIR"
mkdir -p "$(dirname "$JUNIT")"

python3 -B -m unittest discover -s src/tests -p test_ci_release.py -v
python3 -B scripts/ci/package_metadata.py --check-config-only
bash src/scripts/build.sh configure
bash src/scripts/build.sh build
bash src/scripts/build.sh test --junit "$JUNIT"
bash src/scripts/build.sh package

DEB="$BUILD_DIR/altprobe_${VERSION}_amd64.deb"
python3 -B src/tests/test_package_runtime.py "$DEB"
[[ "$(dpkg-deb -f "$DEB" Package)" == altprobe ]]
[[ "$(dpkg-deb -f "$DEB" Version)" == "$VERSION" ]]
[[ "$(dpkg-deb -f "$DEB" Architecture)" == amd64 ]]
mkdir -p "$DIST_DIR"
cp "$DEB" LICENSE NOTICE "$DIST_DIR/"
python3 -B scripts/ci/package_metadata.py --build-dir "$BUILD_DIR" --junit "$JUNIT" --dist-dir "$DIST_DIR"
echo 'Native and proxy runtime tests, DEB checks, and release metadata verified.'
