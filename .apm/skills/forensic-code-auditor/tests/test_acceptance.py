"""Executable synthetic oracles and report gates; not an LLM detection benchmark."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


validator = module('report_validator', ROOT / 'scripts/validate_report_v1.py')
fixture = module('authorization_fixture', ROOT / 'tests/fixtures/authorization/runtime.py')


def report():
    result = json.loads((ROOT / 'templates/assurance-summary-v1.json').read_text())
    result.update(assurance='PARTIAL', conclusion='INCONCLUSIVE')
    result['scope'][0].update(status='reviewed')
    return result


def finding():
    return dict(id='F-1', operation_id='replace-operation-id', category='AUTHZ-BYPASS',
                tags=['AUTHZ-DATA-INTEGRITY'], severity='HIGH', evidence_status='NON LIQUET',
                verification='NOT_VERIFIED', invariant_source=None, policy_independent=False,
                policy_violation=True, location='configuration.json#L2-rare', proof=[],
                test=dict(executed=False, command='', environment='', result='', durable_effects=''),
                unresolved=['Independent policy baseline unavailable'])


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.rows = fixture.load('configuration.json')['rows']
        self.policy = fixture.load('policy.json')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def runtime(self, rows=None):
        return fixture.Runtime(Path(self.tmp.name) / 'local.sqlite', rows or self.rows)

    def test_01_wrong_row_correct_evaluators_and_durable_effects(self):
        intended, source = fixture.intended(self.policy, 'clerk-1', 'clerk', 'approve', 'north', 'PENDING', 15)
        granted, rows = fixture.effective(self.rows, level=2, role='clerk', resource='APPROVAL_FORM', operation='approve', scope='north', at=15)
        self.assertFalse(intended)
        self.assertTrue(granted)
        self.assertEqual(rows, ['L2-rare'])
        self.assertIn('approved-policy.md', source)
        runtime = self.runtime()
        self.assertTrue(runtime.approve('Forms', 'clerk'))
        self.assertEqual(runtime.durable(), ('APPROVED', 1))

    def test_02_missing_policy_does_not_invent_baseline(self):
        self.assertEqual(fixture.intended(None, 'clerk-1', 'clerk', 'approve', 'north', 'PENDING', 15), (None, None))
        r = report(); f = finding(); r['findings'] = [f]
        self.assertEqual(validator.validate(r), [])
        r['conclusion'] = 'FINDINGS_REPORTED'; f.update(evidence_status='SUSPECTED', invariant_source='configuration.json')
        self.assertTrue(any('independent policy' in e for e in validator.validate(r)))

    def test_03_documented_exception_and_time_scope(self):
        self.assertEqual(fixture.intended(self.policy, 'relief-clerk', 'clerk', 'approve', 'north', 'PENDING', 15), (True, 'approved-policy.md#e-relief'))
        self.assertFalse(fixture.intended(self.policy, 'relief-clerk', 'clerk', 'approve', 'north', 'PENDING', 20)[0])
        self.assertIsNone(fixture.intended(self.policy, 'relief-clerk', 'clerk', 'approve', 'south', 'PENDING', 15)[0])

    def test_04_navigation_bypass_reaches_mutation(self):
        rows = copy.deepcopy(self.rows); rows[1]['allow'] = False
        runtime = self.runtime(rows)
        self.assertFalse(runtime.approve('Forms', 'clerk'))
        self.assertEqual(runtime.durable(), ('PENDING', 0))
        self.assertTrue(runtime.approve('REST', 'clerk'))
        self.assertEqual(runtime.durable(), ('APPROVED', 1))

    def test_04b_boundary_guard_blocks_same_api(self):
        runtime = self.runtime()
        self.assertFalse(runtime.approve('REST', 'clerk', boundary_check=True))
        self.assertEqual(runtime.durable(), ('PENDING', 0))

    def test_04c_scoped_delegation_is_authorized(self):
        allow, _ = fixture.intended(self.policy, 'relief-clerk', 'clerk', 'approve', 'north', 'PENDING', 15)
        runtime = self.runtime()
        self.assertTrue(runtime.approve('REST', 'clerk', boundary_check=True, delegated=allow))
        self.assertEqual(runtime.durable(), ('APPROVED', 1))

    def test_06_assurance_gate(self):
        for conclusion in ('SECURE', 'PASS', 'NO_FINDINGS_IN_VERIFIED_SCOPE'):
            r = report(); r['conclusion'] = conclusion
            self.assertTrue(validator.validate(r), conclusion)
        r = report(); r['assurance'] = 'VERIFIED_SCOPE'
        self.assertTrue(validator.validate(r))

    def test_07_unexecuted_test_cannot_be_dynamic_confirmation(self):
        r = report(); f = finding(); r['findings'] = [f]
        f.update(verification='TEST_GENERATED')
        self.assertEqual(validator.validate(r), [])
        f.update(verification='DYNAMIC_REPRODUCED')
        self.assertTrue(any('actual execution' in e for e in validator.validate(r)))
        f.update(verification='TEST_GENERATED', evidence_status='CONFIRMED')
        self.assertTrue(validator.validate(r))

    def test_08_safety_rejects_live_report_environment(self):
        r = report(); r['conclusion'] = 'FINDINGS_REPORTED'; f = finding(); r['findings'] = [f]
        f.update(evidence_status='CONFIRMED', verification='DYNAMIC_REPRODUCED', policy_independent=True,
                 invariant_source='approved-policy.md#p-approve', proof=['local test output'])
        f['test'].update(executed=True, command='unittest', environment='production', result='reproduced', durable_effects='APPROVED; effects=1')
        self.assertTrue(any('environment' in e for e in validator.validate(r)))
        f['test']['environment'] = 'isolated-local-synthetic'
        self.assertEqual(validator.validate(r), [])

    def test_effective_precedence_conflicts_and_expiry(self):
        rows = copy.deepcopy(self.rows)
        deny = dict(rows[1], id='deny-tie', allow=False)
        rows.append(deny)
        args = dict(level=2, role='clerk', resource='APPROVAL_FORM', operation='approve', scope='north', at=15)
        self.assertFalse(fixture.effective(rows, **args)[0])
        rows.append(dict(deny, id='override', priority=2, role='*', resource='*', allow=True))
        self.assertEqual(fixture.effective(rows, **args), (True, ['override']))
        args['at'] = 100
        self.assertEqual(fixture.effective(rows, **args), (False, []))

    def test_validator_rejects_omissions_duplicates_unknown_operations(self):
        for mutate in (
            lambda r: r['operations'][0]['completion'].pop('entry_points'),
            lambda r: r['scope'].append(copy.deepcopy(r['scope'][0])),
            lambda r: r.update(findings=[dict(finding(), operation_id='absent')]),
        ):
            r = report(); mutate(r)
            self.assertTrue(validator.validate(r))

    def test_verified_scope_requires_all_completion_evidence(self):
        r = report(); r.update(assurance='VERIFIED_SCOPE', conclusion='NO_FINDINGS_IN_VERIFIED_SCOPE')
        r['scope'][0].update(status='verified', evidence=['synthetic trace'], limitations=[])
        for item in r['operations'][0]['completion'].values():
            item.update(status='complete', evidence=['synthetic trace'], needed='')
        self.assertEqual(validator.validate(r), [])
        r['operations'][0]['completion']['invariant']['evidence'] = []
        self.assertTrue(validator.validate(r))


if __name__ == '__main__':
    unittest.main()
