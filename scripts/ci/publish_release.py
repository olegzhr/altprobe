"""Upload verified artifacts after a successful merge; never print credentials."""
from pathlib import Path
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

API = 'https://api.github.com'
REPOSITORY = 'olegzhr/altprobe'
TAG = 'v1.0.2'
TARGET_BRANCHES = ('main', 'master')


class GitHub:
    def __init__(self, token):
        self.token = token

    def request(self, method, url, *, data=None, binary=None):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname not in ('api.github.com', 'uploads.github.com'):
            raise ValueError('Unexpected GitHub API/upload host')
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Altprobe-GitHub-Actions'}
        payload = None
        if data is not None:
            payload = json.dumps(data).encode()
            headers['Content-Type'] = 'application/json'
        if binary is not None:
            payload = binary
            headers['Content-Type'] = 'application/octet-stream'
        request = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            # GitHub may echo request details; never print response bodies or headers.
            raise RuntimeError(f'GitHub {method} failed: HTTP {error.code}') from None


def list_assets(client, release):
    base = f'{API}/repos/{REPOSITORY}/releases/{release["id"]}/assets'
    assets = {}
    page = 1
    while True:
        batch = client.request('GET', f'{base}?per_page=100&page={page}')
        assets.update((asset['name'], asset) for asset in batch)
        if len(batch) < 100:
            return assets
        page += 1


def ensure_asset(client, release, assets, name, content):
    digest = 'sha256:' + hashlib.sha256(content).hexdigest()
    asset = assets.get(name)
    if asset and asset.get('state') == 'starter':
        client.request('DELETE', f'{API}/repos/{REPOSITORY}/releases/assets/{asset["id"]}')
        asset = None
    if not asset:
        upload = release['upload_url'].split('{', 1)[0]
        asset = client.request('POST', upload + '?name=' + urllib.parse.quote(name, safe=''), binary=content)
    if asset.get('digest') != digest or asset.get('size') != len(content):
        raise RuntimeError('Published artifact digest/size mismatch: ' + name)


RELEASE_FILES = ('altprobe_1.0.2_amd64.deb', 'build-provenance.json', 'LICENSE', 'NOTICE', 'SHA256SUMS')
POINTER = re.compile(r'<!-- altprobe-release: ([0-9a-f]{64}-altprobe-release\.json) -->')


def publish_snapshot(client, release, dist):
    local = {name: (dist / name).read_bytes() for name in RELEASE_FILES}
    hashes = {name: hashlib.sha256(content).hexdigest() for name, content in local.items()}
    expected_sums = [f'{hashes[name]}  {name}' for name in sorted(hashes.keys() - {'SHA256SUMS'})]
    if local['SHA256SUMS'].decode('utf-8').splitlines() != expected_sums:
        raise RuntimeError('SHA256SUMS differs from the verified release files')
    files = {name: {'asset': f'{digest}-{name}', 'sha256': digest} for name, digest in hashes.items()}
    assets = list_assets(client, release)
    for name, entry in files.items():
        ensure_asset(client, release, assets, entry['asset'], local[name])
    manifest = (json.dumps({'schema': 1, 'version': '1.0.2', 'files': files}, sort_keys=True) + '\n').encode('utf-8')
    manifest_name = hashlib.sha256(manifest).hexdigest() + '-altprobe-release.json'
    ensure_asset(client, release, assets, manifest_name, manifest)

    # The release body is the only mutable pointer. A reader that saw the old
    # pointer can still fetch every referenced asset after a new publication.
    release_url = f'{API}/repos/{REPOSITORY}/releases/{release["id"]}'
    body = client.request('GET', release_url).get('body') or ''
    existing = POINTER.findall(body)
    if len(existing) > 1:
        raise RuntimeError('More than one Altprobe release pointer')
    if existing == [manifest_name]:
        return
    marker = f'<!-- altprobe-release: {manifest_name} -->'
    updated = POINTER.sub(lambda _: marker, body) if existing else body.rstrip() + '\n\n' + marker
    client.request('PATCH', release_url, data={'body': updated})


def validate_context(env):
    if env.get('GITHUB_EVENT_NAME') != 'push':
        raise RuntimeError('Release publishing is allowed only after a push to main or master')
    if env.get('GITHUB_REF_NAME') not in TARGET_BRANCHES:
        raise RuntimeError('Release publishing is allowed only from main or master')
    if env.get('GITHUB_REPOSITORY') != REPOSITORY:
        raise RuntimeError('Release publishing is allowed only from ' + REPOSITORY)
    if env.get('ALTPROBE_VERSION', '1.0.2') != '1.0.2':
        raise RuntimeError('Unexpected product version')


def protected_branch(client, branch):
    if branch not in TARGET_BRANCHES:
        raise RuntimeError('Unexpected target branch: ' + str(branch))
    details = client.request('GET', f'{API}/repos/{REPOSITORY}/branches/{branch}')
    if not isinstance(details, dict) or details.get('protected') is not True:
        raise RuntimeError('Release publishing requires a protected target branch')


def merged_request(client, env):
    commit = env['GITHUB_SHA']
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise RuntimeError('Invalid GitHub commit identity')
    pulls = client.request('GET', f'{API}/repos/{REPOSITORY}/commits/{commit}/pulls')
    return next((pull['number'] for pull in pulls
                 if pull.get('merged_at') and pull.get('base', {}).get('ref') == env['GITHUB_REF_NAME']), None)


def main():
    validate_context(os.environ)
    token = os.environ.get('GITHUB_TOKEN', '')
    if not token:
        raise RuntimeError('Missing GITHUB_TOKEN for the release workflow')
    client = GitHub(token)
    protected_branch(client, os.environ['GITHUB_REF_NAME'])
    request_number = merged_request(client, os.environ)
    if request_number is None:
        print('No merged pull request for this commit; GitHub publication skipped.')
        return
    print('Publishing verified merged pull request #' + str(request_number))
    root = Path(__file__).resolve().parents[2]
    provenance = json.loads((root / 'dist/build-provenance.json').read_text())
    if provenance['version'] != '1.0.2' or provenance['commit'] != os.environ['GITHUB_SHA']:
        raise RuntimeError('Build provenance does not match this workflow commit')
    package = root / 'dist/altprobe_1.0.2_amd64.deb'
    if hashlib.sha256(package.read_bytes()).hexdigest() != provenance['package_sha256']:
        raise RuntimeError('Package checksum differs from verified build')
    # The requested v1.0.2 release already exists. Never move its tag or create a tag from an unrelated branch.
    release = client.request('GET', f'{API}/repos/{REPOSITORY}/releases/tags/{TAG}')
    if release['tag_name'] != TAG or release.get('immutable'):
        raise RuntimeError('Release tag mismatch or immutable release')
    publish_snapshot(client, release, root / 'dist')
    print('Release updated: ' + release['html_url'])


if __name__ == '__main__':
    main()
