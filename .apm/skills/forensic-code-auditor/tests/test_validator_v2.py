"""Evidence/coverage attack regressions equivalent to reported review mechanisms."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import validate_report as validator

CATEGORIES = ['ui_entry','menu_node','policy_store','stored_procedure','db_grant','api_route','gateway','queue_consumer','batch_job','scheduler','mcp_tool','db_link','direct_db_access']
ITEMS = ['invariant','entry_points','policy_provenance','execution_trace','competing_defenses','failure_hypothesis','discriminating_proof','classification','coverage']


def write_ref(root, name, value):
    p = root / name; p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(value if isinstance(value, str) else json.dumps(value))
    return {'path': name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}


def golden(root):
    source = write_ref(root, 'target.sql', 'PROCEDURE approve IS BEGIN NULL; END;\n')
    policy = write_ref(root, 'policy.json', {'rows': [{'id': 'P1', 'allow': False}]})
    graph = write_ref(root, 'operations.json', {'schema_version': 1, 'operations': [{'id': 'approve','class': 'lifecycle'}], 'edges': [], 'limitations': [], 'categories': {'stored_procedure': ['approve'], 'policy_store': ['permissions']}})
    configuration = write_ref(root, 'configuration.json', {'rows':[{'id':'R1'}],'nodes':[{'id':'N1'}]})
    coverage = write_ref(root, 'coverage.json', {'row_ratio': 1.0, 'node_ratio': 1.0, 'decision_ratio': 1.0, 'semantics_assumed': [], 'semantics_sources':{k:source for k in ('inheritance','conflict','null_scope','default','precedence')},'rows_inspected':1,'nodes_inspected':1,'decisions':1,'limitations': []})
    matrix = write_ref(root, 'matrix.csv', 'principal,operation,intended,configured\na,approve,DENY,DENY\n')
    diff = write_ref(root, 'diff.json', [])
    return {'schema_version': 2, 'assurance': 'VERIFIED_SCOPE','conclusion': 'NO_FINDINGS_IN_VERIFIED_SCOPE',
            'scope': {'categories': [{'category': c, 'status': 'verified' if c in ('stored_procedure','policy_store') else 'absent', 'critical': c in ('stored_procedure','policy_store'), 'operation_ids': ['approve'] if c == 'stored_procedure' else [], 'evidence': [source], 'limitations': []} for c in CATEGORIES]},
            'operations': [{'id': 'approve','class': 'lifecycle','status': 'complete','reason': '', 'completion': {k: {'status': 'complete','evidence': [source], 'needed': ''} for k in ITEMS}}],
            'findings': [], 'references_loaded': [], 'tools_executed': [],
            'artifacts': [{'kind': k, 'ref': r} for k,r in [('configuration.json',configuration),('operations.json', graph),('coverage.json',coverage),('matrix.csv',matrix),('diff.json',diff)]],
            'discovery': graph}


def finding(root):
    ref = {'path': 'target.sql','sha256': hashlib.sha256((root/'target.sql').read_bytes()).hexdigest(),'line': 1}
    policy = {'path': 'policy.json','sha256': hashlib.sha256((root/'policy.json').read_bytes()).hexdigest(),'row_key': 'P1'}
    return {'id': 'F1', 'operation_id': 'approve','category': 'AUTHZ-BYPASS','tags': ['AUTHZ-DATA-INTEGRITY'], 'severity': 'HIGH','evidence_status': 'CONFIRMED','verification': 'STATIC_PROVEN', 'policy_basis': {'class': 'requirement_doc','ref': policy},'location': ref,'proof': [ref], 'entry_points': ['Forms'], 'contributing_rows': [policy], 'paths': [{'entry_point': 'Forms','edges': [{'from': 'Forms','to': 'approve','kind': 'call','status': 'established','evidence_ref': ref}]}], 'unresolved': []}


class ValidatorV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.report = golden(self.root)

    def check(self, report=None):
        return validator.validate(report or self.report, evidence_root=self.root)

    def test_golden_artifacts_and_static_dossier(self):
        self.assertEqual(self.check(), [])
        self.report['findings'] = [finding(self.root)]
        self.report['conclusion'] = 'FINDINGS_REPORTED'
        self.assertEqual(self.check(), [])

    def test_requires_evidence_root_and_all_categories(self):
        self.assertTrue(validator.validate(self.report))
        self.report['scope']['categories'].pop()
        self.assertTrue(self.check())

    def test_tampered_file_missing_file_line_and_row(self):
        for mutation in ('tamper','missing','line','row'):
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(self.report); r['findings'] = [finding(self.root)]; r['conclusion'] = 'FINDINGS_REPORTED'
                ref = r['findings'][0]['location']
                if mutation == 'tamper': ref['sha256'] = '0'*64
                if mutation == 'missing': ref['path'] = 'absent.sql'
                if mutation == 'line': ref['line'] = 100
                if mutation == 'row': r['findings'][0]['policy_basis']['ref']['row_key'] = 'absent'
                self.assertTrue(self.check(r))

    def test_path_traversal_absolute_and_symlink_escape(self):
        for path in ('../escape','/etc/hosts','https://example.test/a'):
            r = copy.deepcopy(self.report); r['discovery']['path'] = path
            self.assertTrue(self.check(r))
        (self.root/'escape').symlink_to(self.root.parent)
        r = copy.deepcopy(self.report); r['discovery']['path'] = 'escape/file'
        self.assertTrue(self.check(r))

    def test_omitted_criticality_and_deferred_operation(self):
        self.report['operations'] = []
        self.assertTrue(self.check())
        self.report = golden(self.root)
        self.report['scope']['categories'][3]['critical'] = False
        self.report['scope']['categories'][3]['operation_ids'] = []
        self.assertTrue(self.check())
        self.report = golden(self.root)
        self.report['operations'][0].update(status='deferred', reason='out of budget')
        self.assertTrue(self.check())
        self.report.update(assurance='PARTIAL', conclusion='INCONCLUSIVE')
        self.assertEqual(self.check(), [])

    def test_nonliquet_and_unexamined_cannot_be_clean(self):
        for status in ('NON LIQUET','SUSPECTED'):
            r = copy.deepcopy(self.report); f = finding(self.root)
            f.update(evidence_status=status, verification='NOT_VERIFIED', unresolved=['Missing export'])
            r['findings'] = [f]
            self.assertTrue(self.check(r))
        self.report['scope']['categories'][0].update(status='unexamined',limitations=['Unavailable UI'])
        self.assertTrue(self.check())

    def test_policy_cannot_be_opted_out(self):
        self.report['findings'] = [finding(self.root)]; self.report['conclusion'] = 'FINDINGS_REPORTED'
        for basis in ('derived_from_rows','derived_from_code','derived_from_tests','none'):
            self.report['findings'][0]['policy_basis']['class'] = basis
            self.assertTrue(self.check(), basis)

    def test_fake_dynamic_record_generated_test_and_failed_scanner(self):
        f = finding(self.root); self.report['findings'] = [f]; self.report['conclusion'] = 'FINDINGS_REPORTED'
        f['verification'] = 'DYNAMIC_REPRODUCED'
        self.assertTrue(self.check())
        f['run_record'] = write_ref(self.root,'fake.json',{'command': ['echo','ok'], 'exit_code': 0})
        self.assertTrue(self.check())
        f['verification'] = 'TEST_GENERATED'; self.assertTrue(self.check())
        f['verification'] = 'STATIC_PROVEN'; del f['run_record']
        self.report['tools_executed'] = [{'tool': 'scanner','version': '1','command': ['scanner'],'exit_code': 2,'outcome': 'no_hits','output_ref': f['location']}]
        self.assertTrue(self.check())

    def test_unresolved_discovery_edge_caps_assurance(self):
        graph_path=self.root/'operations.json'
        graph=json.loads(graph_path.read_text())
        graph['edges']=[{'from':'unknown','to':'approve','status':'unresolved'}]
        new_ref=write_ref(self.root,'operations.json',graph)
        self.report['discovery']=new_ref
        next(a for a in self.report['artifacts'] if a['kind']=='operations.json')['ref']=new_ref
        self.assertTrue(self.check())

    def test_coverage_denominator_and_semantics_are_checked(self):
        path=self.root/'coverage.json'
        data=json.loads(path.read_text());data['decisions']=999
        ref=write_ref(self.root,'coverage.json',data)
        next(a for a in self.report['artifacts'] if a['kind']=='coverage.json')['ref']=ref
        self.assertTrue(self.check())
        data['decisions']=1;data['semantics_sources']={'default':'claimed'}
        ref=write_ref(self.root,'coverage.json',data)
        next(a for a in self.report['artifacts'] if a['kind']=='coverage.json')['ref']=ref
        self.assertTrue(self.check())

    def test_no_policy_manifest_or_false_absence(self):
        self.report['scope']['categories'][2]['status'] = 'absent'
        self.assertTrue(self.check())
        self.report = golden(self.root)
        self.report['artifacts'] = [a for a in self.report['artifacts'] if a['kind'] != 'coverage.json']
        self.assertTrue(self.check())

    def test_mixed_repo_unextracted_workflow_and_zero_input_scanner(self):
        graph_path = self.root / 'operations.json'
        graph = json.loads(graph_path.read_text())
        graph['source_digest'] = 'a' * 64
        graph['file_status'] = {'target.sql': 'extracted', '.github/workflows/ci.yml': 'manual_required'}
        new_ref = write_ref(self.root, 'operations.json', graph)
        self.report['discovery'] = new_ref
        next(a for a in self.report['artifacts'] if a['kind'] == 'operations.json')['ref'] = new_ref
        self.assertTrue(any('VERIFIED_SCOPE' in e for e in self.check()))
        self.report = golden(self.root)
        f = finding(self.root)
        f['policy_basis']['class'] = 'platform_spec'
        self.report['findings'] = [f]
        self.report['conclusion'] = 'FINDINGS_REPORTED'
        self.assertEqual(self.check(), [])
        self.report['tools_executed'] = [{'tool': 'semgrep', 'version': '1.182.1', 'command': ['semgrep'], 'exit_code': 0, 'outcome': 'no_hits', 'output_ref': f['location'], 'files_analyzed': 0}]
        self.assertTrue(any('zero analyzed files' in e for e in self.check()))
        self.report['tools_executed'][0]['files_analyzed'] = 3
        self.report['tools_executed'][0]['inputs_digest'] = 'b' * 64
        graph['file_status'] = {'target.sql': 'extracted'}
        new_ref = write_ref(self.root, 'operations.json', graph)
        self.report['discovery'] = new_ref
        next(a for a in self.report['artifacts'] if a['kind'] == 'operations.json')['ref'] = new_ref
        self.assertTrue(any('inputs_digest' in e for e in self.check()))


if __name__ == '__main__': unittest.main()
