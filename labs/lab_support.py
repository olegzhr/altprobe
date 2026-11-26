"""Run-scoped evidence and release provenance for source labs."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'labs/common/altprobe'))
import release_metadata

RELEASE_VERSION = release_metadata.PRODUCT_VERSION
RELEASE_TAG = 'v' + RELEASE_VERSION
RELEASE_BASE_URL = 'https://github.com/olegzhr/altprobe/releases/download'
RELEASE_URL_RE = re.compile(
    r'https://github\.com/[^/]+/[^/]+/releases/download/v' + re.escape(RELEASE_VERSION) + r'$')


def docker(*args: str) -> str:
    result = subprocess.run(['docker', *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f'docker {args[0]} failed: {result.stderr.strip()}')
    return result.stdout.strip()


def input_digest(lab: Path) -> str:
    """Hash code/config only; ignore runtime evidence, private env and PKI."""
    digest = hashlib.sha256()
    files = [ROOT/'labs/lab_support.py', ROOT/'labs/run_source_lab.py']
    for directory in (lab, ROOT/'labs/common/altprobe'):
        files += [p for p in directory.rglob('*') if p.is_file()
                  and not any(part in {'.local', 'results', 'logs', '__pycache__', '.pytest_cache'} for part in p.parts)
                  and (p.name == 'Dockerfile' or p.suffix in {'.py', '.sh', '.yaml', '.yml', '.json', '.lua', '.txt', '.co'})
                  and not p.name.startswith('.env')]
    for path in sorted(set(files), key=lambda p: p.relative_to(ROOT).as_posix()):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def release_package_digest(timeout: float = 30) -> str:
    """Resolve the current release assets and return the package digest."""
    files = release_metadata.release_files(RELEASE_BASE_URL, RELEASE_VERSION, timeout)
    return files[release_metadata.package_name(RELEASE_VERSION)]['sha256']


def release_receipt(container: str) -> dict:
    """Read the image release receipt and hash the binary that is actually running."""
    script = ('import hashlib,json,pathlib; '
              'p=pathlib.Path("/usr/local/share/altprobe/release-receipt.json"); '
              'r=json.loads(p.read_text()); '
              'r["actual_binary_sha256"]=hashlib.sha256(pathlib.Path("/usr/local/bin/altprobe").read_bytes()).hexdigest(); '
              'print(json.dumps(r))')
    return json.loads(docker('exec', container, 'python3', '-c', script))


def verify_release(receipt: dict) -> None:
    """Reject images that were not installed from the published release asset."""
    if receipt.get('schema') != 1 or receipt.get('source') != 'github-release':
        raise AssertionError('Altprobe image was not installed from the GitHub release')
    if receipt.get('version') != RELEASE_VERSION or receipt.get('release_tag') != RELEASE_TAG:
        raise AssertionError(f'Altprobe image does not contain release {RELEASE_TAG}')
    if not RELEASE_URL_RE.fullmatch(receipt.get('release_url', '')):
        raise AssertionError('Altprobe image was installed from an unexpected release URL')
    for key in ('package_sha256', 'binary_sha256'):
        if not re.fullmatch(r'[0-9a-f]{64}', receipt.get(key, '')):
            raise AssertionError(f'Altprobe release receipt has an invalid {key}')
    if receipt['binary_sha256'] != receipt['actual_binary_sha256']:
        raise AssertionError('Running binary mismatch: installed Altprobe differs from the release receipt')


def compose_digest(lab: Path, run_id: str) -> str:
    config = json.loads(docker('compose', '-f', str(lab/'docker-compose.yaml'),
                               '-f', str(lab/'.local'/run_id/'compose.json'), 'config', '--format', 'json'))
    # Hash the rendered private config; never store or print secret values.
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def load_run(lab: Path) -> dict:
    path = lab / '.local/current-run.json'
    if not path.exists():
        raise AssertionError(f'No current run receipt. Use python labs/run_source_lab.py {lab.name[4:]} start from the repository root.')
    run = json.loads(path.read_text(encoding='utf-8'))
    if run.get('schema') != 1 or run.get('lab') != lab.name or not run.get('run_id'):
        raise AssertionError('Invalid lab run receipt')
    assert 0 <= int(time.time()*1000) - run['started_ms'] < 24*3600*1000, 'Run receipt expired; start a new run'
    assert run.get('release_tag') == RELEASE_TAG, 'Run receipt uses a different Altprobe release'
    assert run['inputs_sha256'] == input_digest(lab), 'Lab code/config changed after start'
    assert run['compose_sha256'] == compose_digest(lab, run['run_id']), 'Rendered Compose config changed after start'
    for service, expected in run['services'].items():
        info = json.loads(docker('inspect', expected['container']))[0]
        assert info['Image'] == expected['image'], f'{service}: image changed'
        assert info['State']['StartedAt'] == expected['started_at'], f'{service}: restarted after receipt'
        assert info['Config']['Labels'].get('org.altprobe.lab.run_id') == run['run_id'], f'{service}: wrong run'
        state = info['State']
        if service == 'agent' or service.endswith('-init'):
            assert state['Status'] in {'running', 'exited'}, f'{service}: unhealthy lifecycle'
            if state['Status'] == 'exited':
                assert state['ExitCode'] == 0, f'{service}: failed with exit {state["ExitCode"]}'
        else:
            assert state['Running'], f'{service}: not running'
            assert state.get('Health', {}).get('Status') != 'unhealthy', f'{service}: unhealthy'
    actual = release_receipt(run['services']['altprobe']['container'])
    verify_release(actual)
    assert actual['package_sha256'] == run['package_sha256'], 'Running image installed a different release package'
    assert actual['binary_sha256'] == run['binary_sha256'], 'Running binary mismatch: image changed'
    return run


def fresh(run: dict, record: dict) -> bool:
    timestamp = record.get('time')
    return isinstance(timestamp, (int, float)) and run['started_ms'] <= timestamp <= int(time.time()*1000) + 60000


def query(run: dict) -> dict:
    return {'range': {'time': {'gte': run['started_ms'], 'lte': int(time.time()*1000) + 60000}}}


def evidence_path(lab: Path, run: dict) -> Path:
    return lab / '.local' / run['run_id'] / 'evidence'
