"""Canonical enums and local routes must agree with the structured contract."""
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from stage_package import stage
from contamination_lint import check

ROOT=Path(__file__).resolve().parents[1]
REFERENCE_PROCEDURES = (
    'auditing-data-lifecycles.md', 'auditing-resource-budgets.md',
    'auditing-message-authority.md', 'auditing-local-authority.md',
    'revalidating-audits.md', 'reviewing-audit-evidence.md',
)


class DocTests(unittest.TestCase):
    def test_reference_names_and_direct_routes(self):
        router = (ROOT / 'SKILL.md').read_text()
        self.assertLessEqual(len(router.splitlines()), 80)
        for folder in ('references', 'agents'):
            for path in (ROOT / folder).rglob('*.md'):
                self.assertNotIn('_', path.name, str(path))
        for name in REFERENCE_PROCEDURES:
            self.assertIn('(references/' + name + ')', router)
            self.assertTrue((ROOT / 'references' / name).is_file())

    def test_enums_and_links(self):
        schema=json.loads((ROOT/'templates/report.schema.json').read_text())
        instructions=(ROOT/'instructions.md').read_text()
        finding=schema['properties']['findings']['items']['properties']
        for name,values in [('Evidence',finding['evidence_status']['enum']),('Verification',finding['verification']['enum']),('Severity',finding['severity']['enum']),('Assurance',schema['properties']['assurance']['enum']),('Conclusion',schema['properties']['conclusion']['enum'])]:
            line=next(line for line in instructions.splitlines() if line.startswith('**'+name+':**'))
            self.assertEqual(set(re.findall(r'`([^`]+)`',line)),set(values))
        errors=[]
        for p in ROOT.rglob('*.md'):
            if any(part.endswith('.testproj') for part in p.parts):continue
            for target in re.findall(r'\]\(([^)]+)\)',p.read_text()):
                target=target.split('#',1)[0]
                if target and '://' not in target and not target.startswith('mailto:') and not (p.parent/target).exists():errors.append(str(p)+': '+target)
        self.assertEqual(errors,[])

    def test_runtime_stage_contains_no_evaluation_material(self):
        with tempfile.TemporaryDirectory() as folder:
            destination=stage(ROOT,Path(folder)/'runtime')
            self.assertEqual(check(destination),[])
            self.assertFalse((destination/'tests').exists());self.assertFalse((destination/'evals').exists())
            self.assertTrue((destination/'scripts/authz_effective.py').is_file())
            for name in REFERENCE_PROCEDURES:
                self.assertTrue((destination / 'references' / name).is_file())
            self.assertTrue((destination / 'agents/forensic-systems-analyst.md').is_file())
            notice = (destination / 'assets/cloudflare-security-audit-skill.LICENSE').read_text()
            self.assertIn('Copyright (c) 2025-2026 Cloudflare, Inc.', notice)
            self.assertIn('Permission is hereby granted', notice)


if __name__=='__main__':unittest.main()
