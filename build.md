# Build Altprobe from source

Build from the repository root on Ubuntu 22.04 or in WSL 2 with Ubuntu 22.04.
The build uses the collector, tests and vendored OTLP definitions under `src/`.

## Install build dependencies

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config python3 \
  libboost-thread-dev libboost-iostreams-dev libboost-regex-dev \
  libhiredis-dev libyaml-cpp-dev libmodsecurity-dev libssl-dev libdaemon-dev \
  zlib1g-dev protobuf-compiler protobuf-compiler-grpc libgrpc++-dev libprotobuf-dev \
  dpkg-dev ca-certificates curl
```

## Local build helper

`src/scripts/build.sh` is the supported local entry point. It configures,
compiles and runs the CTest suite:

```bash
bash src/scripts/build.sh
```

Commands and options:

```bash
bash src/scripts/build.sh configure        # CMake only
bash src/scripts/build.sh build            # configure and compile
bash src/scripts/build.sh test             # CTest only
bash src/scripts/build.sh package          # altprobe_1.0.2_amd64.deb
bash src/scripts/build.sh clean            # remove the build directory

bash src/scripts/build.sh all --build-dir "$HOME/build-altprobe" --jobs 4 \
  --junit native-tests.xml
```

`ALTPROBE_BUILD_DIR` selects the build directory (default `build/`),
`BUILD_JOBS` the number of parallel jobs. `--no-crs` builds the package without
the bundled OWASP CRS, and `--debug` selects `CMAKE_BUILD_TYPE=Debug`.

When the source lives on a Windows drive under WSL, keep the build directory on
the Linux filesystem: linking and archiving on `/mnt/c` is extremely slow. The
helper prints a warning when the build directory is under `/mnt/`.

The equivalent manual commands are:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
build/src/altprobe status
```

## Build the Debian package

```bash
bash scripts/ci/build-test-package.sh
```

This command runs the release guards, builds and tests the tree through
`src/scripts/build.sh`, builds the package and verifies the DEB. It writes
`altprobe_1.0.2_amd64.deb`, `SHA256SUMS`, `build-provenance.json`, `LICENSE`
and `NOTICE` to `dist/`, and `native-tests.xml` to the repository root. To keep
compiler artifacts on the WSL filesystem, set `ALTPROBE_BUILD_DIR` to an
absolute path. `BUILD_JOBS`, `ALTPROBE_DIST_DIR` and `ALTPROBE_JUNIT` override
the other build outputs. For an offline build with an existing OWASP CRS
archive, set `ALTPROBE_CRS_ARCHIVE` and `ALTPROBE_CRS_ARCHIVE_SHA256` to the
archive path and its trusted SHA-256.

The package installs the collector and its service helpers under
`/usr/local/bin` and configuration under `/etc/altprobe`. Build the package on
the Ubuntu release used for deployment so that the shared library dependencies
resolved by `dpkg-shlibdeps` match the target system.

The source-builder container compiles and tests the same tree without touching
the host toolchain:

```bash
docker build -f docker/Dockerfile.build -t altprobe:build .
```

## Continuous integration

`.github/workflows/ci.yml` runs the same verification on GitHub-hosted runners
(`ubuntu-22.04`) for every push to `master`/`main` and for every pull request:
it installs the build dependencies, runs `scripts/ci/build-test-package.sh`,
publishes `dist/` and `native-tests.xml` as the `altprobe-release` artifact and
prints `build-provenance.json`.

Publishing the `v1.0.2` release assets runs in the `publish-release` job after a
push to a protected `master`/`main`. It requires a merged pull request for the
pushed commit, verifies the protected branch through the GitHub API, compares
`build-provenance.json` with the workflow commit and the package checksum, and
uploads the files under SHA-256-qualified names. After GitHub confirms their
digests and sizes, one API update selects the new manifest in the release
notes. Existing release snapshots stay downloadable while readers verify the
exact files they selected. The workflow uses `GITHUB_TOKEN` (`contents: write`).
Pull-request and manual runs never publish; they only attach artifacts.

The build records the checkout commit and exact source and package digests.
Published-release image builds use `docker/Dockerfile` and verify the package
checksum from the release.
