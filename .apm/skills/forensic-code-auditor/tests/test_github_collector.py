"""Collector authority, pagination and unknown-state regressions; no network calls."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from collect_github_security import collect, plan, request


def response(status=200, more=False, exit_code=0, body='{"environments": []}', extra_headers=''):
    headers = 'HTTP/2.0 '+str(status)+' Status\n' + extra_headers
    if more:
        headers += 'Link: <https://api.github.com/unused>; rel="next"\n'
    return subprocess.CompletedProcess([], exit_code, headers+'\n'+body, '')


class CollectorTests(unittest.TestCase):
    def test_fixed_scope_and_encoded_segments(self):
        paths = dict(plan('owner/repo', ['feature/x'], ['prod/a'], ['123']))
        self.assertIn('user', paths)
        self.assertIn('repos/owner/repo/actions/oidc/customization/sub', paths)
        self.assertIn('repos/owner/repo/actions/caches', paths)
        self.assertIn('repos/owner/repo/branches/feature%2Fx/protection', paths)
        self.assertIn('repos/owner/repo/environments/prod%2Fa/secrets', paths)
        self.assertIn('repos/owner/repo/environments/prod%2Fa/deployment-branch-policies', paths)
        self.assertIn('repos/owner/repo/actions/runs/123', paths)
        self.assertIn('repos/owner/repo/actions/runs/123/artifacts', paths)
        for repo in ('https://example.test/r', '../repo', 'owner/..', '--help'):
            with self.assertRaises(ValueError):
                plan(repo)
        with self.assertRaises(ValueError):
            plan('owner/repo', runs=['1/../../secrets'])

    @patch('collect_github_security.subprocess.run')
    def test_request_is_get_with_fixed_host_and_debug_disabled(self, mocked):
        with patch.dict('os.environ', {'GH_DEBUG': 'api', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'inert-oidc'}):
            request('repos/owner/repo', 10)
        argv = mocked.call_args.args[0]
        self.assertEqual(argv[argv.index('--method')+1], 'GET')
        self.assertEqual(argv[argv.index('--hostname')+1], 'github.com')
        self.assertNotIn('GH_DEBUG', mocked.call_args.kwargs['env'])
        self.assertNotIn('ACTIONS_ID_TOKEN_REQUEST_TOKEN', mocked.call_args.kwargs['env'])
        self.assertFalse(mocked.call_args.kwargs['shell'])

    def collect_mock(self, replies, **kwargs):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)/'evidence'
            with patch('collect_github_security.plan', return_value=[('repos/o/r/environments', True)]), \
                 patch('collect_github_security.request', side_effect=replies) as mocked:
                result = collect('o/r', output, **kwargs)
                self.assertEqual(json.loads((output/'manifest.json').read_text()), result)
                return result, mocked.call_args_list

    def test_pagination_completes_and_artifacts_are_bound(self):
        result, calls = self.collect_mock([response(more=True), response()])
        self.assertTrue(result['collection_complete'])
        self.assertIn('page=2', calls[1].args[0])
        self.assertEqual(len(result['queries'][0]['pages'][0]['stdout']['sha256']), 64)

    def test_denied_and_404_are_unknown(self):
        for status in (403, 404):
            with self.subTest(status=status):
                result, _ = self.collect_mock([response(status, exit_code=1)])
                self.assertFalse(result['collection_complete'])
                self.assertEqual(result['queries'][0]['state'], 'UNKNOWN')
                self.assertEqual(result['queries'][0]['pages'][0]['http_status'], status)

    def test_page_limit_timeout_and_invalid_json_are_unknown(self):
        for reply in (response(more=True), subprocess.TimeoutExpired('gh', 1),
                      subprocess.CompletedProcess([], 0, 'invalid', '')):
            with self.subTest(reply=reply):
                result, _ = self.collect_mock([reply], max_pages=1)
                self.assertFalse(result['collection_complete'])
                self.assertIn('error', result['queries'][0]['pages'][-1])

    def test_existing_directory_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileExistsError):
                collect('owner/repo', Path(folder))

    def test_collector_fetches_ruleset_details_and_records_oauth_scopes(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)/'evidence'
            planned = [
                ('user', False),
                ('repos/octo/demo/rulesets?includes_parents=true', True),
                ('repos/octo/demo/actions/runs/7/artifacts', True),
            ]
            replies = [
                response(body='{"login": "auditor-bot", "type": "User"}',
                         extra_headers='X-OAuth-Scopes: repo, read:org\nX-Accepted-OAuth-Scopes: repo\n'),
                response(body='[{"id": 42, "name": "main-protection", "enforcement": "active"}]',
                         extra_headers='X-OAuth-Scopes: repo, read:org\n'),
                response(body='{"total_count": 1, "artifacts": [{"id": 501, "name": "scan-report", "digest": "sha256:inert000"}]}'),
                response(body='{"id": 42, "bypass_actors": [{"actor_id": 99, "actor_type": "Integration", "bypass_mode": "always"}], "rules": [{"type": "required_status_checks"}]}'),
            ]
            with patch('collect_github_security.plan', return_value=planned), \
                 patch('collect_github_security.request', side_effect=replies):
                manifest = collect('octo/demo', output, runs=['7'])
            self.assertTrue(manifest['collection_complete'])
            self.assertFalse(manifest['required_controls_complete'])
            self.assertEqual(manifest['caller'], {'login': 'auditor-bot', 'type': 'User'})
            self.assertEqual(manifest['queries'][0]['pages'][0]['oauth_scopes'], ['repo', 'read:org'])
            endpoints = [q['endpoint'] for q in manifest['queries']]
            self.assertIn('repos/octo/demo/rulesets/42', endpoints)
            self.assertIn('repos/octo/demo/actions/runs/7/artifacts', endpoints)
            self.assertEqual(manifest['control_coverage']['ruleset_details_and_bypass_actors'], 'observed')
            self.assertEqual(manifest['control_coverage']['branch_protection'], 'not_requested')
            self.assertEqual(manifest['control_coverage']['copilot_and_cloud_iam'], 'owner_export_required')

    def test_endpoint_wrong_shape_and_multiple_header_blocks(self):
        bad, _ = self.collect_mock([response(body='{}')])
        self.assertFalse(bad['collection_complete'])
        self.assertEqual(bad['queries'][0]['state'], 'UNKNOWN')
        self.assertIn('expected object with environments list', bad['queries'][0]['pages'][0]['error'])
        redirected = subprocess.CompletedProcess(
            [], 0,
            'HTTP/1.1 302 Found\nLocation: https://api.github.com/redirect\n\nHTTP/2.0 200 OK\n\n{"environments": [{"id": 1}]}',
            ''
        )
        ok, _ = self.collect_mock([redirected])
        self.assertTrue(ok['collection_complete'])
        self.assertEqual(ok['queries'][0]['state'], 'COLLECTED')


if __name__ == '__main__':
    unittest.main()
