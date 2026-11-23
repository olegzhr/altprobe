"""Verify packaged binary/configs and write public provenance without credentials."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src/scripts'))
from build_receipt import source_digest


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-config-only', action='store_true')
    parser.add_argument('--build-dir', type=Path, default=ROOT / 'build-ci')
    parser.add_argument('--junit', type=Path, default=ROOT / 'native-tests.xml')
    parser.add_argument('--dist-dir', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    config_dir = ROOT / 'src/etc'
    configuration = (config_dir / 'altprobe.yaml').read_text(encoding='utf-8')
    for field in ('af_key', 'os_pwd', 'splunk_token', 'bearer_token', 'redis_password'):
        # A release configuration may only carry an empty value; trailing
        # comments such as "af_key: \"\"   # SINKS_AF_KEY" are not credentials.
        matches = re.findall(r'^\s*' + field + r'\s*:\s*([^#\n]*)', configuration, re.M)
        assert len(matches) == 1 and matches[0].strip() in ('', '""', "''"), 'Release configuration must not contain credentials: ' + field
    if args.check_config_only:
        return
    version = os.environ.get('ALTPROBE_VERSION', '1.0.2')
    assert version == '1.0.2'
    package = args.dist_dir / f'altprobe_{version}_amd64.deb'
    binary = args.build_dir / 'src/altprobe'
    with tempfile.TemporaryDirectory(prefix='altprobe-package-') as folder:
        extracted = Path(folder)
        subprocess.run(['dpkg-deb', '--extract', str(package), folder], check=True)
        control = extracted / 'control-metadata'
        subprocess.run(['dpkg-deb', '--control', str(package), str(control)], check=True)
        conffiles = (control / 'conffiles').read_text().splitlines()
        for name in ('altprobe.yaml', 'api_guard.yaml', 'scoring_weights.yaml', 'sbom.yaml'):
            assert '/etc/altprobe/' + name in conffiles, 'User configuration must be a dpkg conffile: ' + name
        assert sha(extracted / 'usr/local/bin/altprobe') == sha(binary)
        configs = {}
        for name in ('altprobe.yaml', 'api_guard.yaml', 'scoring_weights.yaml', 'sbom.yaml'):
            digest = sha(config_dir / name)
            assert sha(extracted / 'etc/altprobe' / name) == digest
            configs[name] = digest
        assert (extracted / 'etc/altprobe/coreruleset/rules').is_dir(), 'OWASP CRS missing'
    junit = ET.parse(args.junit).getroot()
    cases = list(junit.iter('testcase'))
    assert len(cases) >= 10 and not any(list(junit.iter(tag)) for tag in ('failure', 'error', 'skipped'))
    assert any(case.get('name') == 'test_proxy_runtime' for case in cases)
    commit = None
    if (ROOT / '.git').exists():
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    inputs = hashlib.sha256((sha(ROOT / 'CMakeLists.txt') + source_digest(ROOT / 'src') +
                             source_digest(ROOT / 'scripts/ci')).encode('ascii')).hexdigest()
    metadata = {
        'product': 'Altprobe', 'version': version,
        'commit': commit, 'source_sha256': inputs,
        'pipeline_id': os.environ.get('GITHUB_RUN_ID') or os.environ.get('CI_PIPELINE_ID'),
        'job_id': os.environ.get('GITHUB_JOB') or os.environ.get('CI_JOB_ID'),
        'native_tests_passed': len(cases), 'proxy_runtime': 'PASS',
        'binary_sha256': sha(binary),
        'package': package.name, 'package_sha256': sha(package), 'configuration_sha256': configs,
        'compiler': subprocess.check_output(['c++', '--version'], text=True).splitlines()[0],
        'cmake': subprocess.check_output(['cmake', '--version'], text=True).splitlines()[0],
    }
    provenance = args.dist_dir / 'build-provenance.json'
    provenance.write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    files = sorted([package, provenance, args.dist_dir / 'LICENSE', args.dist_dir / 'NOTICE'])
    (args.dist_dir / 'SHA256SUMS').write_text(''.join(f'{sha(path)}  {path.name}\n' for path in files), encoding='utf-8')
    print(json.dumps({'package': package.name, 'sha256': sha(package), 'tests': len(cases)}))


if __name__ == '__main__':
    main()
