"""Delete legacy SHA-256-qualified snapshot assets from the v1.0.2 release.

The release now publishes canonical asset names. Older publications left
``<sha256>-<name>`` assets and a ``<sha256>-altprobe-release.json`` manifest
behind; they are no longer referenced by the labs. Dry-run by default.

    GITHUB_TOKEN=... python3 scripts/ci/prune_release_snapshots.py
    GITHUB_TOKEN=... python3 scripts/ci/prune_release_snapshots.py --apply
"""
from pathlib import Path
import argparse
import os
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from publish_release import API, REPOSITORY, TAG, GitHub, list_assets  # noqa: E402

SNAPSHOT = re.compile(r'[0-9a-f]{64}-(?:(?:altprobe_1\.0\.2_amd64\.deb)|build-provenance\.json|LICENSE|NOTICE|SHA256SUMS|altprobe-release\.json)$')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='delete the assets (default: list only)')
    args = parser.parse_args()
    token = os.environ.get('GITHUB_TOKEN', '')
    if not token:
        raise SystemExit('GITHUB_TOKEN is required')
    client = GitHub(token)
    release = client.request('GET', f'{API}/repos/{REPOSITORY}/releases/tags/{TAG}')
    legacy = sorted(name for name in list_assets(client, release) if SNAPSHOT.fullmatch(name))
    if not legacy:
        print('No legacy snapshot assets.')
        return 0
    for name in legacy:
        print(name)
    if not args.apply:
        print(f'{len(legacy)} legacy asset(s); rerun with --apply to delete them.')
        return 0
    assets = list_assets(client, release)
    for name in legacy:
        client.request('DELETE', f'{API}/repos/{REPOSITORY}/releases/assets/{assets[name]["id"]}')
        print('deleted', name)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
