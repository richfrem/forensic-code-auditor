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

## Global APM hooks and upstream repairs

Universal agent tooling is installed globally through APM. A hook failure in this repository may
originate from an upstream package rather than the forensic auditor. Inspect `~/.apm/apm.yml`,
`~/.apm/apm.lock.yaml` and `~/.codex/hooks.json` to identify the owning package and deployed script.
The `agent-agentic-os` package owns the metrics and turn-evolution Stop hooks;
`agent-orchestration` owns the loop-closure Stop hook. Check for duplicate registrations.

Repair these packages in `../agent-plugins-skills/plugins/<package>/.apm/hooks/`, never in deployed
`~/.codex/hooks/`, skill copies or plugin caches. Use a feature branch, reproduce the protocol failure
with disposable local fixtures, run the relevant tests, and submit the fix through a GitHub PR when
authorized. Codex Stop-hook stdout must conform to its JSON protocol; keep diagnostics on stderr.
Preserve guard decisions and distinguish empty output from malformed non-empty output in tests.

After the user merges the PR, verify its merged state, return the source checkout to `main`, pull
`origin main` without discarding local work, and remove the merged feature branch/worktree. Reinstall
the affected package globally through the APM workflow, previewing changes and backing up global
install state first. Verify deployed code and hook output; do not claim a fix is active before reinstall.

## Commands

Run from the skill source directory:

```bash
python3 -m pip install -r requirements-tests.txt
python3 -m unittest discover -s tests -v
python3 scripts/demo_authorization.py --output /tmp/forensic-auditor-demo
python3 scripts/validate_report.py /tmp/forensic-auditor-demo/report.json --evidence-root /tmp/forensic-auditor-demo
semgrep --test references/rules/semgrep
python3 scripts/test_codeql.py
```

CodeQL harness exit 77 means NOT RUN, not success. Schema v2 requires artifact-aware validation; v1 is legacy structural validation. Preserve existing valid fixtures and record scanner
false positives. Use the isolated consumer packaging workflow in [INSTALL.md](INSTALL.md); packing the dependency-free
source root does not include its authored source. Root `apm.lock.yaml` is local development state and ignored.
