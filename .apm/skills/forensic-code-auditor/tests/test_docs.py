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


class DocTests(unittest.TestCase):
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


if __name__=='__main__':unittest.main()
