#!/usr/bin/env python3
"""Build/start source labs from the published Altprobe release with a verifiable run receipt."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from lab_support import (RELEASE_TAG, ROOT, compose_digest, docker, input_digest,
                         release_package_digest, release_receipt, verify_release)


def make_override(config: dict, lab_name: str, run_id: str, evidence: Path) -> dict:
    services = {name: {'labels': {'org.altprobe.lab.run_id': run_id}}
                for name in config['services']}
    for name in ('agent', 'mock', 'claude', 'traffic'):
        if name in services:
            services[name]['environment'] = {'LAB_RUN_ID': run_id}
    if lab_name == 'nemo':
        for name in ('agent', 'mock'):
            services[name]['volumes'] = [f'{evidence.as_posix()}:/evidence']
    if lab_name == 'sbom':
        services['altprobe']['environment'] = {'ALTPROBE_ASSET_NAME': 'sbom-target-' + run_id}
    return {'services': services}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lab', choices=['nemo', 'sbom', 'suricata'])
    parser.add_argument('action', choices=['start', 'test', 'stop'])
    args = parser.parse_args()
    lab = ROOT / 'labs' / ('lab_' + args.lab)
    receipt = lab / '.local/current-run.json'
    base = ['compose', '-f', str(lab/'docker-compose.yaml')]
    if args.action != 'start':
        assert receipt.exists(), 'Start the lab with this runner first'
        run = json.loads(receipt.read_text())
        command = base + ['-f', str(lab/'.local'/run['run_id']/'compose.json')]
        if args.action == 'stop':
            docker(*command, 'down')  # No -v: retain data, PKI and Trivy cache.
        else:
            result = subprocess.run([os.sys.executable, str(lab/'tests'/f'test_{args.lab}.py')])
            raise SystemExit(result.returncode)
        return

    # A failed new start must not leave an earlier run eligible for a PASS.
    if receipt.exists(): receipt.unlink()
    run_id = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8]
    directory = lab / '.local' / run_id
    evidence = directory/'evidence'
    evidence.mkdir(parents=True)
    config = json.loads(docker(*base, 'config', '--format', 'json'))
    override = directory/'compose.json'
    override.write_text(json.dumps(make_override(config, args.lab, run_id, evidence), indent=2), encoding='utf-8')
    command = base + ['-f', str(override)]
    package = release_package_digest()
    inputs = input_digest(lab)
    rendered = compose_digest(lab, run_id)
    print(f'Building {lab.name} from Altprobe release {RELEASE_TAG}, run={run_id}', flush=True)
    subprocess.run(['docker', *command, 'build', '--build-arg', 'ALTPROBE_PACKAGE_SHA256=' + package], check=True)
    assert (input_digest(lab) == inputs and compose_digest(lab, run_id) == rendered), 'Inputs changed during build'
    started = int(time.time()*1000)
    subprocess.run(['docker', *command, 'up', '-d', '--force-recreate'], check=True)
    observed = {}
    for name in config['services']:
        ids = docker(*command, 'ps', '-a', '-q', name).splitlines()
        assert len(ids) == 1, f'{name}: expected one container'
        info = json.loads(docker('inspect', ids[0]))[0]
        observed[name] = {'container': info['Id'], 'image': info['Image'], 'started_at': info['State']['StartedAt']}
    binary = release_receipt(observed['altprobe']['container'])
    verify_release(binary)
    assert binary['package_sha256'] == package, 'Image installed a different release package'
    run = {'schema': 1, 'lab': lab.name, 'run_id': run_id, 'started_ms': started,
           'release_tag': RELEASE_TAG, 'package_sha256': package,
           'binary_sha256': binary['binary_sha256'],
           'inputs_sha256': inputs, 'compose_sha256': rendered,
           'services': observed}
    receipt.write_text(json.dumps(run, indent=2), encoding='utf-8')
    (directory/'run.json').write_text(json.dumps(run, indent=2), encoding='utf-8')
    if args.lab == 'suricata':
        for sensor in ('traffic', 'suricata', 'shipper'):
            assert json.loads(docker('inspect', observed[sensor]['container']))[0]['State']['Running'], f'{sensor}: not running'
    print(f'Receipt: {receipt}\nTest: python labs/run_source_lab.py {args.lab} test')


if __name__ == '__main__':
    main()
