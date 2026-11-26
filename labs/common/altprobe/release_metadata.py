"""Verify the published Altprobe package and record its release provenance.

The labs never compile Altprobe from source. Every image downloads the canonical
release assets (``altprobe_<version>_amd64.deb`` and ``SHA256SUMS``) from the
GitHub release, verifies every file against ``SHA256SUMS``, and records the
exact package digest. A running container can therefore be traced back to the
release asset instead of a mutable checkout.

Asset names are stable across publications, so a plain URL works:

    https://github.com/olegzhr/altprobe/releases/download/v1.0.2/altprobe_1.0.2_amd64.deb
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

PRODUCT_VERSION = '1.0.2'
RECEIPT_SCHEMA = 1
SAFE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*')
SUMS_LINE = re.compile(r'([0-9a-fA-F]{64})\s+\*?(?:\./)?(.+)')
# Temporary compatibility with SHA-256-qualified snapshots published before the
# switch to canonical asset names; removed once no such release remains.
POINTER = re.compile(r'<!-- altprobe-release: ([0-9a-f]{64}-altprobe-release\.json) -->')
GITHUB_BASE = re.compile(r'https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/releases/download')


def package_name(version: str) -> str:
    """Return the release asset name and refuse any other product version."""
    if version != PRODUCT_VERSION:
        raise ValueError(f'Unsupported Altprobe version {version!r}; expected {PRODUCT_VERSION}')
    return f'altprobe_{version}_amd64.deb'


def release_file_names(version: str) -> set:
    """Return the files that a complete release publication must provide."""
    return {package_name(version), 'build-provenance.json', 'LICENSE', 'NOTICE'}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def checksum(sums_text: str, filename: str) -> str:
    """Return the single SHA256SUMS entry for ``filename``."""
    entries = [digest for name, digest in parse_sums(sums_text).items() if name == filename]
    if len(entries) != 1:
        raise ValueError(f'Expected exactly one SHA256SUMS entry for {filename}')
    return entries[0]


def parse_sums(sums_text: str) -> dict:
    """Parse SHA256SUMS into ``{name: digest}`` while rejecting unsafe names."""
    entries = {}
    for line in sums_text.splitlines():
        if not line.strip():
            continue
        match = SUMS_LINE.fullmatch(line.strip())
        if not match:
            raise ValueError('Malformed SHA256SUMS line')
        digest, name = match.group(1).lower(), match.group(2)
        if not SAFE_NAME.fullmatch(name):
            raise ValueError('Unsafe file name in SHA256SUMS: ' + name)
        if name in entries:
            raise ValueError('Duplicate SHA256SUMS entry: ' + name)
        entries[name] = digest
    if not entries:
        raise ValueError('Empty SHA256SUMS')
    return entries


def verify_package(package: Path, sums: Path, version: str) -> str:
    """Verify ``package`` against its release SHA256SUMS and return the digest."""
    name = package_name(version)
    package, sums = Path(package), Path(sums)
    if package.name != name:
        raise ValueError(f'Expected release asset {name}, got {package.name}')
    expected = checksum(sums.read_text(encoding='utf-8'), name)
    actual = sha256(package)
    if actual != expected:
        raise ValueError(f'Release package checksum mismatch for {name}')
    return actual


def release_url(base_url: str, version: str) -> str:
    base = base_url.rstrip('/')
    tag = f'v{version}'
    if base.endswith('/' + tag):
        return base
    return f'{base}/{tag}'


def fetch(url: str, timeout: float) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        data = response.read(1048577)
    if len(data) > 1048576:
        raise ValueError('Release metadata exceeds size limit')
    return data


def _canonical_entries(base_url: str, version: str, timeout: float = 30) -> dict:
    base = release_url(base_url, version)
    sums = parse_sums(fetch(f'{base}/SHA256SUMS', timeout).decode('utf-8'))
    expected = release_file_names(version)
    missing = expected - set(sums)
    unexpected = set(sums) - expected
    if missing:
        raise ValueError('Release SHA256SUMS is missing: ' + ', '.join(sorted(missing)))
    if unexpected:
        raise ValueError('Release SHA256SUMS lists unexpected files: ' + ', '.join(sorted(unexpected)))
    return {name: {'asset': name, 'sha256': digest} for name, digest in sums.items()}


def _legacy_entries(base_url: str, version: str, timeout: float) -> dict:
    """Read a SHA-256-qualified snapshot published by an older workflow.

    Temporary compatibility path: the current release may still only contain
    ``<sha256>-<name>`` assets plus a manifest pointer in the release body. New
    publications use canonical names, so this path disappears on its own.
    """
    base = release_url(base_url, version)
    github = GITHUB_BASE.fullmatch(base.removesuffix('/v' + version))
    if not github:
        raise ValueError('Release has no canonical SHA256SUMS')
    release = json.loads(fetch(f'https://api.github.com/repos/{github[1]}/releases/tags/v{version}', timeout))
    markers = POINTER.findall(release.get('body') or '')
    if len(markers) > 1:
        raise ValueError('More than one Altprobe release pointer')
    if not markers:
        raise ValueError('Release has no canonical SHA256SUMS and no snapshot manifest')
    raw = fetch(f'{base}/{markers[0]}', timeout)
    if hashlib.sha256(raw).hexdigest() != markers[0].split('-', 1)[0]:
        raise ValueError('Release manifest checksum mismatch')
    manifest = json.loads(raw)
    files = manifest.get('files', {})
    if manifest.get('schema') != 1 or manifest.get('version') != version:
        raise ValueError('Invalid release manifest')
    expected = release_file_names(version) | {'SHA256SUMS'}
    if set(files) != expected:
        raise ValueError('Invalid release manifest file set')
    entries = {}
    for filename, entry in files.items():
        digest = entry.get('sha256', '')
        if not re.fullmatch(r'[0-9a-f]{64}', digest) or entry.get('asset') != f'{digest}-{filename}':
            raise ValueError('Invalid release artifact in manifest: ' + filename)
        if filename in release_file_names(version):
            entries[filename] = {'asset': entry['asset'], 'sha256': digest}
    return entries


def _release_entries(base_url: str, version: str, timeout: float = 30) -> dict:
    try:
        return _canonical_entries(base_url, version, timeout)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        return _legacy_entries(base_url, version, timeout)


def release_files(base_url: str, version: str, timeout: float = 30) -> dict:
    """Return ``{name: {'asset': asset, 'sha256': digest}}`` for a release."""
    return _release_entries(base_url, version, timeout)


def download_release(base_url: str, version: str, directory: Path, expected: str = '') -> None:
    entries = _release_entries(base_url, version)
    name = package_name(version)
    if expected and entries[name]['sha256'] != expected:
        raise ValueError('Release package differs from the selected digest')
    base = release_url(base_url, version)
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.altprobe-download-', dir=directory) as staging:
        staging = Path(staging)
        for filename, entry in entries.items():
            target = staging / filename
            with urllib.request.urlopen(f'{base}/{entry["asset"]}', timeout=30) as response, target.open('wb') as out:
                shutil.copyfileobj(response, out)
            if sha256(target) != entry['sha256']:
                raise ValueError('Release artifact checksum mismatch: ' + filename)
        (staging / 'SHA256SUMS').write_text(
            ''.join(f'{entries[filename]["sha256"]}  {filename}\n' for filename in sorted(entries)), encoding='utf-8')
        verify_package(staging / name, staging / 'SHA256SUMS', version)
        for target in staging.iterdir():
            target.replace(directory / target.name)


def provenance(version: str, base_url: str, package_sha256: str, binary: Path) -> dict:
    """Describe the installed release without any local source dependency."""
    if not re.fullmatch(r'[0-9a-f]{64}', package_sha256 or ''):
        raise ValueError('Invalid release package digest')
    return {
        'schema': RECEIPT_SCHEMA,
        'source': 'github-release',
        'version': version,
        'release_tag': f'v{version}',
        'package': package_name(version),
        'release_url': release_url(base_url, version),
        'package_sha256': package_sha256,
        'binary_sha256': sha256(binary),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--package')
    parser.add_argument('--sums')
    parser.add_argument('--download-dir', type=Path)
    parser.add_argument('--print-package-sha256', action='store_true')
    parser.add_argument('--expected-sha256', default='')
    parser.add_argument('--binary', default='/usr/local/bin/altprobe')
    parser.add_argument('--receipt')
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()

    if args.download_dir:
        download_release(args.base_url, args.version, args.download_dir, args.expected_sha256)
        return 0
    if args.print_package_sha256:
        print(_release_entries(args.base_url, args.version)[package_name(args.version)]['sha256'])
        return 0
    if not args.package or not args.sums:
        parser.error('--package and --sums are required for local verification')

    digest = verify_package(Path(args.package), Path(args.sums), args.version)
    if args.verify_only:
        return 0
    if not args.receipt:
        raise SystemExit('--receipt is required unless --verify-only is used')
    value = provenance(args.version, args.base_url, digest, Path(args.binary))
    receipt = Path(args.receipt)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
