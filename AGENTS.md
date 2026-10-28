# Project instructions: Forensic Code Auditor

Standalone forensic code logic and invariant auditing skill distributed through APM.

## Navigation

- [Architecture](ARCHITECTURE.md)
- [Installation and migration](INSTALL.md)
- [Canonical skill source](.apm/skills/forensic-code-auditor/SKILL.md)
- [Tests and limits](.apm/skills/forensic-code-auditor/TESTING.md)

## Invariants

1. Treat software as deterministic state machines bounded by physical, resource and informational limits.
2. Vendor claims, compliance badges and passing scans are not proof of safety. Platform specifications
   and DBMS manuals may establish mechanical semantics.
3. Separate evidence status, verification state, impact severity and assurance coverage. Cite invariant
   sources; independently source intended business policy rather than trusting code/current rows/tests.
4. Preserve Step 0 plus the seven-step forensic method. Discover surfaces before conditional routing;
   record missing entry paths and complete or explicitly leave unresolved all operation contract items.
5. Reproductions use explicitly authorized disposable local environments and synthetic data only.
6. Edit `.apm/skills/forensic-code-auditor/`, never installed `.agents`, `.claude` or other harness copies.
7. Keep target checkouts in ignored `repos/`; private findings, local state and evidence belong in ignored
   `temp/` or `evidence/`. Runtime downloads, installed tools and private recovery bundles are not public assets.
8. Crow and Raven may be optional local tools/targets; do not add them as package dependencies.
9. Do not claim a tool compiled, a test executed or detection improved without actual recorded results.

## Commands

Run from the skill source directory:

```bash
python3 -m pip install -r requirements-tests.txt
python3 -m unittest discover -s tests -v
python3 scripts/demo_authorization.py --output /tmp/forensic-auditor-demo
python3 scripts/validate_report.py /tmp/forensic-auditor-demo/report.json
semgrep --test references/rules/semgrep
python3 scripts/test_codeql.py
```

CodeQL harness exit 77 means NOT RUN, not success. Preserve existing valid fixtures and record scanner
false positives. Use the isolated consumer packaging workflow in [INSTALL.md](INSTALL.md); packing the dependency-free
source root does not include its authored source. Root `apm.lock.yaml` is local development state and ignored.
