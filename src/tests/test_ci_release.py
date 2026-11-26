import hashlib
import importlib.util
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

    def test_run_identifier_is_required(self):
        self.assertEqual(publisher.run_id({'GITHUB_RUN_ID': '12', 'GITHUB_RUN_ATTEMPT': '3'}), '12-3')
        with self.assertRaises(RuntimeError):
            publisher.run_id({'GITHUB_RUN_ID': 'abc'})


class ReleasePublication(unittest.TestCase):
    def test_canonical_assets_are_replaced_and_notes_written_once(self):
        with tempfile.TemporaryDirectory() as folder:
            dist = self.release_files(Path(folder))
            client = self.AssetClient()
            publisher.publish_assets(client, client.release, dist, '1-1', 'f' * 40)
            self.assertEqual(sorted(client.assets), sorted(publisher.RELEASE_FILES))
            for name in publisher.RELEASE_FILES:
                self.assertEqual(client.assets[name]['data'], (dist / name).read_bytes())
            self.assertEqual(client.updates, 1)
            self.assertIn('sha256:', client.body)
            self.assertNotIn('altprobe-release.json', client.body)
            uploads = client.uploads
            publisher.publish_assets(client, client.release, dist, '1-2', 'f' * 40)
            self.assertEqual(client.uploads, uploads)
            self.assertEqual(client.updates, 1)

    def test_previous_asset_is_renamed_and_deleted_after_success(self):
        with tempfile.TemporaryDirectory() as folder:
            dist = self.release_files(Path(folder))
            client = self.AssetClient()
            client.seed_asset('LICENSE', b'old license')
            publisher.publish_assets(client, client.release, dist, '7-1', 'f' * 40)
            self.assertEqual(client.assets['LICENSE']['data'], (dist / 'LICENSE').read_bytes())
            self.assertIn(('LICENSE', 'LICENSE.previous-7-1'), client.renames)
            self.assertIn('LICENSE.previous-7-1', client.deleted)

    def test_failed_upload_keeps_previous_assets_and_notes(self):
        with tempfile.TemporaryDirectory() as folder:
            dist = self.release_files(Path(folder))
            client = self.AssetClient(fail_at=3)
            client.seed_asset('LICENSE', b'old license')
            with self.assertRaisesRegex(RuntimeError, 'Upload failed'):
                publisher.publish_assets(client, client.release, dist, '1-1', 'f' * 40)
            self.assertEqual(client.assets['LICENSE']['data'], b'old license')
            self.assertEqual(client.body, 'Release notes')
            self.assertEqual(client.updates, 0)

    def test_sha256sums_mismatch_is_rejected_before_any_upload(self):
        with tempfile.TemporaryDirectory() as folder:
            dist = self.release_files(Path(folder))
            (dist / 'SHA256SUMS').write_text('0' * 64 + '  LICENSE\n', encoding='utf-8')
            client = self.AssetClient()
            with self.assertRaisesRegex(RuntimeError, 'SHA256SUMS differs'):
                publisher.publish_assets(client, client.release, dist, '1-1', 'f' * 40)
            self.assertEqual(client.uploads, 0)
            self.assertEqual(client.updates, 0)

    @staticmethod
    def release_files(dist):
        files = sorted(set(publisher.RELEASE_FILES) - {'SHA256SUMS'})
        for name in files:
            (dist / name).write_bytes(name.encode())
        (dist / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256((dist / name).read_bytes()).hexdigest()}  {name}\n'
            for name in files), encoding='utf-8')
        return dist

    class AssetClient:
        release = {'id': 1, 'upload_url': 'https://uploads.github.com/test{?name}'}

        def __init__(self, fail_at=None):
            self.fail_at = fail_at
            self.assets = {}
            self.body = 'Release notes'
            self.uploads = self.updates = 0
            self.next_id = 100
            self.renames = []
            self.deleted = set()

        def seed_asset(self, name, content):
            self.assets[name] = {
                'id': self.next_id, 'name': name, 'size': len(content), 'data': content,
                'digest': 'sha256:' + hashlib.sha256(content).hexdigest()}
            self.next_id += 1

        def asset_by_id(self, url):
            asset_id = int(url.rstrip('/').rsplit('/', 1)[1])
            return next(asset for asset in self.assets.values() if asset['id'] == asset_id)

        def request(self, method, url, **kwargs):
            if method == 'GET':
                return list(self.assets.values()) if '/assets?' in url else {'body': self.body}
            if method == 'POST':
                self.uploads += 1
                if self.uploads == self.fail_at:
                    raise RuntimeError('Upload failed')
                name = parse_qs(urlparse(url).query)['name'][0]
                data = kwargs['binary']
                asset = {'id': self.next_id, 'name': name, 'size': len(data), 'data': data,
                         'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}
                self.next_id += 1
                self.assets[name] = asset
                return asset
            if method == 'PATCH':
                if 'body' in kwargs['data']:
                    self.body = kwargs['data']['body']
                    self.updates += 1
                    return {'body': self.body}
                asset = self.asset_by_id(url)
                new_name = kwargs['data']['name']
                self.renames.append((asset['name'], new_name))
                del self.assets[asset['name']]
                asset['name'] = new_name
                self.assets[new_name] = asset
                return {'name': new_name}
            if method == 'DELETE':
                asset = self.asset_by_id(url)
                del self.assets[asset['name']]
                self.deleted.add(asset['name'])
                return None
            raise AssertionError('Unexpected API call')


if __name__ == '__main__':
    unittest.main()
