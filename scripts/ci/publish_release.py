"""Publish the verified release assets under their canonical asset names.

The release keeps stable file names (``altprobe_1.0.2_amd64.deb``,
``SHA256SUMS``, ``build-provenance.json``, ``LICENSE``, ``NOTICE``), so a plain
download URL always works and no manifest indirection is needed. A new
publication replaces the content of those assets atomically per file: the new
upload is verified first, the old asset is renamed aside, the new one takes the
canonical name, and only then is the old asset deleted.
"""
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
RELEASE_FILES = ('altprobe_1.0.2_amd64.deb', 'build-provenance.json', 'LICENSE', 'NOTICE', 'SHA256SUMS')
NOTE = re.compile(r'<!-- altprobe-release: [^>]*-->\n?')


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


def replace_asset(client, release, assets, name, content, run_id):
    """Give ``name`` exactly ``content``; return True when something changed."""
    digest = 'sha256:' + hashlib.sha256(content).hexdigest()
    existing = assets.get(name)
    if existing and existing.get('digest') == digest and existing.get('size') == len(content):
        return False

    assets_url = f'{API}/repos/{REPOSITORY}/releases/assets/'
    upload = release['upload_url'].split('{', 1)[0]
    temporary = f'{name}.upload-{run_id}'
    stale = assets.get(temporary)
    if stale:
        client.request('DELETE', assets_url + str(stale['id']))
        assets.pop(temporary, None)

    uploaded = client.request('POST', upload + '?name=' + urllib.parse.quote(temporary, safe=''), binary=content)
    uploaded_url = assets_url + str(uploaded['id'])
    if uploaded.get('size') != len(content) or uploaded.get('digest') != digest:
        client.request('DELETE', uploaded_url)
        raise RuntimeError('Uploaded artifact digest/size mismatch: ' + name)

    old_url = None
    if existing:
        old_url = assets_url + str(existing['id'])
        client.request('PATCH', old_url, data={'name': name + '.previous-' + run_id})
    try:
        client.request('PATCH', uploaded_url, data={'name': name})
    except Exception:
        if old_url:
            client.request('PATCH', old_url, data={'name': name})
        client.request('DELETE', uploaded_url)
        raise
    if old_url:
        client.request('DELETE', old_url)
        assets.pop(name, None)
    uploaded['name'] = name
    assets[name] = uploaded
    return True


def write_release_note(client, release, package_sha256, commit=''):
    """Describe the current publication in the release body; idempotent."""
    release_url = f'{API}/repos/{REPOSITORY}/releases/{release["id"]}'
    body = client.request('GET', release_url).get('body') or ''
    marker = f'<!-- altprobe-release: sha256:{package_sha256} -->'
    if marker in body:
        return False
    cleaned = NOTE.sub('', body).rstrip()
    details = [f'`{RELEASE_FILES[0]}` sha256 `{package_sha256}`']
    if commit:
        details.append(f'commit `{commit[:12]}`')
    note = marker + '\n' + 'Release assets use stable names: ' + ', '.join(details) + '. Verify with `SHA256SUMS`.'
    updated = (cleaned + '\n\n' if cleaned else '') + note + '\n'
    client.request('PATCH', release_url, data={'body': updated})
    return True


def publish_assets(client, release, dist, run_id, commit=''):
    local = {name: (dist / name).read_bytes() for name in RELEASE_FILES}
    hashes = {name: hashlib.sha256(content).hexdigest() for name, content in local.items()}
    expected_sums = [f'{hashes[name]}  {name}' for name in sorted(hashes.keys() - {'SHA256SUMS'})]
    if local['SHA256SUMS'].decode('utf-8').splitlines() != expected_sums:
        raise RuntimeError('SHA256SUMS differs from the verified release files')
    assets = list_assets(client, release)
    for name in RELEASE_FILES:
        replace_asset(client, release, assets, name, local[name], run_id)
    write_release_note(client, release, hashes[RELEASE_FILES[0]], commit)


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


def run_id(env):
    value = env.get('GITHUB_RUN_ID', '') + '-' + env.get('GITHUB_RUN_ATTEMPT', '1')
    if not re.fullmatch(r'[0-9]+-[0-9]+', value):
        raise RuntimeError('Invalid workflow run identifier')
    return value


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
    publish_assets(client, release, root / 'dist', run_id(os.environ), os.environ['GITHUB_SHA'])
    print('Release updated: ' + release['html_url'])


if __name__ == '__main__':
    main()
