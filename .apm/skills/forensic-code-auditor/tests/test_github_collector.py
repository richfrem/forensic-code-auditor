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


def response(status=200, more=False, exit_code=0):
    headers = 'HTTP/2.0 '+str(status)+' Status\n'
    if more:
        headers += 'Link: <https://api.github.com/unused>; rel="next"\n'
    return subprocess.CompletedProcess([], exit_code, headers+'\n{}', '')


class CollectorTests(unittest.TestCase):
    def test_fixed_scope_and_encoded_segments(self):
        paths = dict(plan('owner/repo', ['feature/x'], ['prod/a'], ['123']))
        self.assertIn('repos/owner/repo/branches/feature%2Fx/protection', paths)
        self.assertIn('repos/owner/repo/environments/prod%2Fa/secrets', paths)
        self.assertIn('repos/owner/repo/actions/runs/123', paths)
        for repo in ('https://example.test/r', '../repo', 'owner/..', '--help'):
            with self.assertRaises(ValueError):
                plan(repo)
        with self.assertRaises(ValueError):
            plan('owner/repo', runs=['1/../../secrets'])

    @patch('collect_github_security.subprocess.run')
    def test_request_is_get_with_fixed_host_and_debug_disabled(self, mocked):
        with patch.dict('os.environ', {'GH_DEBUG': 'api'}):
            request('repos/owner/repo', 10)
        argv = mocked.call_args.args[0]
        self.assertEqual(argv[argv.index('--method')+1], 'GET')
        self.assertEqual(argv[argv.index('--hostname')+1], 'github.com')
        self.assertNotIn('GH_DEBUG', mocked.call_args.kwargs['env'])
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


if __name__ == '__main__':
    unittest.main()
