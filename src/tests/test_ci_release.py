import hashlib
import importlib.util
import json
from urllib.parse import parse_qs, urlparse
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('publisher', Path(__file__).resolve().parents[2] / 'scripts/ci/publish_release.py')
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


def context(**overrides):
    values = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF_NAME': 'master',
              'GITHUB_REPOSITORY': publisher.REPOSITORY, 'GITHUB_SHA': 'a' * 40,
              'ALTPROBE_VERSION': '1.0.2'}
    values.update(overrides)
    return values


class ReleaseGuards(unittest.TestCase):
    def test_pull_request_cannot_publish(self):
        with self.assertRaises(RuntimeError):
            publisher.validate_context(context(GITHUB_EVENT_NAME='pull_request'))

    def test_manual_run_cannot_publish(self):
        with self.assertRaises(RuntimeError):
            publisher.validate_context(context(GITHUB_EVENT_NAME='workflow_dispatch'))

    def test_other_branch_cannot_publish(self):
        with self.assertRaises(RuntimeError):
            publisher.validate_context(context(GITHUB_REF_NAME='feature/next'))

    def test_other_repository_cannot_publish(self):
        with self.assertRaises(RuntimeError):
            publisher.validate_context(context(GITHUB_REPOSITORY='someone/altprobe'))

    def test_both_target_branch_names_are_supported(self):
        for branch in ('main', 'master'):
            publisher.validate_context(context(GITHUB_REF_NAME=branch))

    def test_unprotected_branch_cannot_publish(self):
        class Client:
            def request(self, method, url):
                return {'name': 'master', 'protected': False}
        with self.assertRaises(RuntimeError):
            publisher.protected_branch(Client(), 'master')

    def test_protected_branch_is_accepted(self):
        class Client:
            def request(self, method, url):
                return {'name': 'master', 'protected': True}
        publisher.protected_branch(Client(), 'master')

    def test_unknown_branch_cannot_be_checked(self):
        class Client:
            def request(self, method, url):
                raise AssertionError('Unexpected API call')
        with self.assertRaises(RuntimeError):
            publisher.protected_branch(Client(), 'release')

    def test_only_merged_pull_request_is_published(self):
        class Client:
            def __init__(self, pulls):
                self.pulls = pulls
            def request(self, method, url):
                assert url.endswith('/pulls'), 'Unexpected API endpoint'
                return self.pulls
        open_request = [{'number': 7, 'merged_at': None, 'base': {'ref': 'master'}}]
        self.assertIsNone(publisher.merged_request(Client(open_request), context()))
        merged = [{'number': 8, 'merged_at': '2026-11-22T00:00:00Z', 'base': {'ref': 'master'}}]
        self.assertEqual(publisher.merged_request(Client(merged), context()), 8)
        other_base = [{'number': 9, 'merged_at': '2026-11-22T00:00:00Z', 'base': {'ref': 'dev'}}]
        self.assertIsNone(publisher.merged_request(Client(other_base), context()))

    def test_invalid_commit_is_rejected(self):
        class Client:
            def request(self, method, url):
                raise AssertionError('Unexpected API call')
        with self.assertRaises(RuntimeError):
            publisher.merged_request(Client(), context(GITHUB_SHA='HEAD'))

    def test_failed_upload_keeps_the_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            dist = self.release_files(Path(folder))
            client = self.SnapshotClient(fail_at=3)
            with self.assertRaisesRegex(RuntimeError, 'Upload failed'):
                publisher.publish_snapshot(client, client.release, dist)
            self.assertEqual(client.body, client.original_body)
            self.assertEqual(client.updates, 0)
            self.assertIn('previous-package', client.assets)

    def test_pointer_switches_only_after_all_assets_exist_and_retries_are_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            dist = self.release_files(Path(folder))
            client = self.SnapshotClient()
            publisher.publish_snapshot(client, client.release, dist)
            self.assertEqual(client.updates, 1)
            self.assertTrue(client.body.startswith('Release notes'))
            self.assertIn('previous-package', client.assets)
            manifest, = publisher.POINTER.findall(client.body)
            self.assertEqual(len(client.assets) - 1, len(publisher.RELEASE_FILES) + 1)
            snapshot = json.loads(client.assets[manifest]['data'])
            for name, entry in snapshot['files'].items():
                self.assertEqual(client.assets[entry['asset']]['data'], (dist / name).read_bytes())
            publisher.publish_snapshot(client, client.release, dist)
            self.assertEqual(client.uploads, len(publisher.RELEASE_FILES) + 1)
            self.assertEqual(client.updates, 1)

    @staticmethod
    def release_files(dist):
        files = sorted(set(publisher.RELEASE_FILES) - {'SHA256SUMS'})
        for name in files:
            (dist / name).write_bytes(name.encode())
        (dist / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256((dist / name).read_bytes()).hexdigest()}  {name}\n'
            for name in files), encoding='utf-8')
        return dist

    class SnapshotClient:
        release = {'id': 1, 'upload_url': 'https://uploads.github.com/test{?name}'}
        original_body = 'Release notes\n\n<!-- altprobe-release: ' + 'a' * 64 + '-altprobe-release.json -->'

        def __init__(self, fail_at=None):
            self.fail_at = fail_at
            self.assets = {'previous-package': {'name': 'previous-package'}}
            self.body = self.original_body
            self.uploads = self.updates = 0

        def request(self, method, url, **kwargs):
            if method == 'GET':
                return list(self.assets.values()) if '/assets?' in url else {'body': self.body}
            if method == 'POST':
                self.uploads += 1
                if self.uploads == self.fail_at:
                    raise RuntimeError('Upload failed')
                name = parse_qs(urlparse(url).query)['name'][0]
                data = kwargs['binary']
                self.assets[name] = {'name': name, 'size': len(data), 'data': data,
                                     'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}
                return self.assets[name]
            if method == 'PATCH':
                body = kwargs['data']['body']
                name, = publisher.POINTER.findall(body)
                for artifact in json.loads(self.assets[name]['data'])['files'].values():
                    assert artifact['asset'] in self.assets
                self.body = body
                self.updates += 1
                return {'body': body}
            raise AssertionError('Unexpected API call')


if __name__ == '__main__':
    unittest.main()
