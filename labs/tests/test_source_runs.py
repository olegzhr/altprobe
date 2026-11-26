"""Offline regressions for release provenance and rejection of historical lab evidence."""
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch

LABS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LABS))
sys.path.insert(0, str(LABS / 'common/altprobe'))
import lab_support as support
import release_metadata


def load_test(name):
    path = LABS / ('lab_' + name) / 'tests' / ('test_' + name + '.py')
    spec = importlib.util.spec_from_file_location('source_test_' + name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


DIGEST = 'a' * 64
OTHER = 'b' * 64


class ReleaseMetadataTests(unittest.TestCase):
    def test_release_resolves_canonical_sha256sums(self):
        names = sorted(release_metadata.release_file_names('1.0.2'))
        sums = ''.join(f'{DIGEST}  {name}\n' for name in names)
        with patch.object(release_metadata, 'fetch', side_effect=[sums.encode()]) as fetch:
            files = release_metadata.release_files(support.RELEASE_BASE_URL, '1.0.2')
        self.assertEqual(sorted(files), names)
        for name, entry in files.items():
            self.assertEqual(entry['asset'], name)
            self.assertEqual(entry['sha256'], DIGEST)
        self.assertTrue(fetch.call_args.args[0].endswith('/SHA256SUMS'))

    def test_incomplete_or_unsafe_sha256sums_is_rejected(self):
        with patch.object(release_metadata, 'fetch',
                          side_effect=[(DIGEST + '  LICENSE\n').encode()]):
            with self.assertRaisesRegex(ValueError, 'missing'):
                release_metadata.release_files(support.RELEASE_BASE_URL, '1.0.2')
        extra = ''.join(f'{DIGEST}  {name}\n' for name in sorted(
            release_metadata.release_file_names('1.0.2') | {'crs.tar.gz'}))
        with patch.object(release_metadata, 'fetch', side_effect=[extra.encode()]):
            with self.assertRaisesRegex(ValueError, 'unexpected'):
                release_metadata.release_files(support.RELEASE_BASE_URL, '1.0.2')
        unsafe = (DIGEST + '  ../altprobe_1.0.2_amd64.deb\n')
        with patch.object(release_metadata, 'fetch', side_effect=[unsafe.encode()]):
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                release_metadata.release_files(support.RELEASE_BASE_URL, '1.0.2')

    def test_legacy_snapshot_manifest_remains_readable(self):
        names = release_metadata.release_file_names('1.0.2')
        files = {filename: {'asset': DIGEST + '-' + filename, 'sha256': DIGEST}
                 for filename in names | {'SHA256SUMS'}}
        manifest = json.dumps({'schema': 1, 'version': '1.0.2', 'files': files}).encode()
        pointer = hashlib.sha256(manifest).hexdigest() + '-altprobe-release.json'
        missing = urllib.error.HTTPError('https://example/v1.0.2/SHA256SUMS', 404, 'Not Found', None, None)
        release = json.dumps({'body': '<!-- altprobe-release: ' + pointer + ' -->'}).encode()
        with patch.object(release_metadata, 'fetch',
                          side_effect=[missing, release, manifest]) as fetch:
            result = release_metadata.release_files(support.RELEASE_BASE_URL, '1.0.2')
        self.assertEqual(result, {filename: files[filename] for filename in names})
        self.assertTrue(fetch.call_args.args[0].endswith(pointer))

    def test_mirror_download_checks_every_artifact_before_replacing_local_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / 'v1.0.2'
            release.mkdir()
            name = release_metadata.package_name('1.0.2')
            payloads = {filename: filename.encode() for filename in release_metadata.release_file_names('1.0.2')}
            (release / 'SHA256SUMS').write_text(''.join(
                f'{hashlib.sha256(data).hexdigest()}  {filename}\n'
                for filename, data in sorted(payloads.items())), encoding='utf-8')
            for filename, data in payloads.items():
                (release / filename).write_bytes(data)
            dest = root / 'download'
            release_metadata.download_release(root.as_uri(), '1.0.2', dest,
                                              hashlib.sha256(payloads[name]).hexdigest())
            self.assertEqual((dest / name).read_bytes(), payloads[name])
            self.assertTrue((dest / 'SHA256SUMS').is_file())
            with self.assertRaisesRegex(ValueError, 'selected digest'):
                release_metadata.download_release(root.as_uri(), '1.0.2', dest, OTHER)
            (release / 'NOTICE').write_bytes(b'CORRUPT')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                release_metadata.download_release(root.as_uri(), '1.0.2', dest)
            self.assertEqual((dest / name).read_bytes(), payloads[name])

    def test_checksum_selects_only_the_package_entry(self):
        sums = (DIGEST + '  LICENSE\n' + OTHER + ' *altprobe_1.0.2_amd64.deb\n'
                + DIGEST + '  build-provenance.json\n')
        self.assertEqual(release_metadata.checksum(sums, 'altprobe_1.0.2_amd64.deb'), OTHER)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            release_metadata.checksum(sums, 'altprobe_1.0.1_amd64.deb')

    def test_unsupported_product_version_is_refused(self):
        self.assertEqual(release_metadata.package_name('1.0.2'), 'altprobe_1.0.2_amd64.deb')
        with self.assertRaisesRegex(ValueError, 'Unsupported Altprobe version'):
            release_metadata.package_name('1.0.3')

    def test_verify_and_provenance_track_the_release_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'altprobe_1.0.2_amd64.deb'
            package.write_bytes(b'release package')
            binary = root / 'altprobe'
            binary.write_bytes(b'installed binary')
            digest = release_metadata.sha256(package)
            sums = root / 'SHA256SUMS'
            sums.write_text(digest + '  altprobe_1.0.2_amd64.deb\n', encoding='utf-8')
            self.assertEqual(release_metadata.verify_package(package, sums, '1.0.2'), digest)
            value = release_metadata.provenance('1.0.2', support.RELEASE_BASE_URL, digest, binary)
            self.assertEqual(value['source'], 'github-release')
            self.assertEqual(value['release_url'], support.RELEASE_BASE_URL + '/v1.0.2')
            self.assertEqual(value['package_sha256'], digest)
            self.assertEqual(value['binary_sha256'], release_metadata.sha256(binary))
            sums.write_text(OTHER + '  altprobe_1.0.2_amd64.deb\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                release_metadata.verify_package(package, sums, '1.0.2')
            with self.assertRaisesRegex(ValueError, 'Invalid release package digest'):
                release_metadata.provenance('1.0.2', support.RELEASE_BASE_URL, 'not-a-digest', binary)


class SourceRunTests(unittest.TestCase):
    def test_lab_and_runtime_images_install_only_the_release_package(self):
        for relative in ('labs/common/altprobe/Dockerfile', 'docker/Dockerfile'):
            text = (LABS.parent / relative).read_text(encoding='utf-8')
            self.assertIn('https://github.com/olegzhr/altprobe/releases/download', text, relative)
            self.assertIn('SHA256SUMS', text, relative)
            self.assertIn('release-receipt.json', text, relative)
            self.assertNotIn('COPY src/', text, relative)
            self.assertNotIn('cmake', text, relative)

    def test_missing_receipt_rejected_before_query(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(AssertionError, 'No current run receipt'):
                support.load_run(Path(directory))

    def test_provenance_drift_and_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / 'lab_nemo'
            (lab / '.local').mkdir(parents=True)
            run = {'schema': 1, 'lab': lab.name, 'run_id': 'new', 'started_ms': int(time.time()*1000),
                   'release_tag': support.RELEASE_TAG, 'package_sha256': DIGEST, 'binary_sha256': OTHER,
                   'inputs_sha256': 'inputs', 'compose_sha256': 'rendered',
                   'services': {'altprobe': {'container': 'container', 'image': 'image', 'started_at': 'start'}}}
            info = {'Image': 'image', 'Config': {'Labels': {'org.altprobe.lab.run_id': 'new'}},
                    'State': {'Running': True, 'StartedAt': 'start'}}
            binary = {'schema': 1, 'source': 'github-release', 'version': support.RELEASE_VERSION,
                      'release_tag': support.RELEASE_TAG,
                      'release_url': support.RELEASE_BASE_URL + '/v1.0.2',
                      'package_sha256': DIGEST, 'binary_sha256': OTHER, 'actual_binary_sha256': OTHER}
            def save(): (lab / '.local/current-run.json').write_text(json.dumps(run))
            save()
            with patch.object(support, 'input_digest', return_value='inputs'), \
                 patch.object(support, 'compose_digest', return_value='rendered'), \
                 patch.object(support, 'docker', side_effect=lambda *_: json.dumps([info])), \
                 patch.object(support, 'release_receipt', return_value=binary):
                self.assertEqual(support.load_run(lab)['run_id'], 'new')
                with patch.object(support, 'compose_digest', return_value='changed'):
                    with self.assertRaisesRegex(AssertionError, 'Rendered Compose config changed'):
                        support.load_run(lab)
                for field, replacement in [('image', 'other'), ('started_at', 'restart')]:
                    old = run['services']['altprobe'][field]
                    run['services']['altprobe'][field] = replacement; save()
                    with self.assertRaises(AssertionError): support.load_run(lab)
                    run['services']['altprobe'][field] = old; save()
                binary['actual_binary_sha256'] = 'modified'
                with self.assertRaisesRegex(AssertionError, 'binary mismatch'): support.load_run(lab)
                binary['actual_binary_sha256'] = OTHER
                binary['source'] = 'local-source'
                with self.assertRaisesRegex(AssertionError, 'not installed from the GitHub release'):
                    support.load_run(lab)
                binary['source'] = 'github-release'
                binary['release_url'] = 'https://example.invalid/altprobe.deb'
                with self.assertRaisesRegex(AssertionError, 'unexpected release URL'):
                    support.load_run(lab)
                binary['release_url'] = support.RELEASE_BASE_URL + '/v1.0.2'
                run['package_sha256'] = OTHER; save()
                with self.assertRaisesRegex(AssertionError, 'different release package'):
                    support.load_run(lab)
                run['package_sha256'] = DIGEST
                run['release_tag'] = 'v1.0.1'; save()
                with self.assertRaisesRegex(AssertionError, 'different Altprobe release'):
                    support.load_run(lab)
                run['release_tag'] = support.RELEASE_TAG; run['started_ms'] = 1; save()
                with self.assertRaisesRegex(AssertionError, 'expired'): support.load_run(lab)

    def test_historical_findings_are_filtered_even_if_server_returns_them(self):
        run = {'run_id': 'new', 'started_ms': int(time.time()*1000)-1000}
        for name, helper in [('nemo', 'findings'), ('sbom', 'fetch_findings'), ('suricata', 'search')]:
            obj = load_test(name); obj.RUN = run
            historical = {'time': 1, 'api': {'operation': '/v1/chat/completions?lab_run_id=new'},
                          'metadata': {'log_name': 'altprobe_sbom', 'uid': 'sbom-target-new:cve'}}
            payload = {'hits': {'hits': [{'_source': historical}]}}
            with patch.object(obj, 'request', return_value=payload):
                result = getattr(obj, helper)('index') if name == 'suricata' else getattr(obj, helper)()
                self.assertEqual(result, [], name)

    def test_nemo_enforcement_requires_agent_refusal_and_no_mock_jailbreak(self):
        obj = load_test('nemo')
        run = {'run_id': 'new', 'started_ms': int(time.time()*1000)-1000}
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            agent = {'run_id': 'new', 'results': [
                {'run_id': 'new', 'case': 'safe', 'blocked': False, 'response': 'mock OpenAI response'},
                {'run_id': 'new', 'case': 'jailbreak', 'blocked': True, 'response': 'Blocked by NeMo Guardrails'}]}
            (evidence/'agent.json').write_text(json.dumps(agent))
            audit = {'run_id': 'new', 'time': int(time.time()*1000), 'markers': [['new', 'safe']]}
            (evidence/'mock.jsonl').write_text(json.dumps(audit)+'\n')
            with patch.object(obj, 'evidence_path', return_value=evidence):
                obj.check_enforcement(run)
                audit['markers'].append(['new', 'jailbreak'])
                (evidence/'mock.jsonl').write_text(json.dumps(audit)+'\n')
                with self.assertRaisesRegex(AssertionError, 'blocked prompt reached mock'):
                    obj.check_enforcement(run)
                agent['results'][1]['blocked'] = False
                (evidence/'agent.json').write_text(json.dumps(agent))
                with self.assertRaisesRegex(AssertionError, 'did not receive refusal'):
                    obj.check_enforcement(run)


if __name__ == '__main__':
    unittest.main()
