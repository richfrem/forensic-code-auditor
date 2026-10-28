# Testing and interpretation

## Reproduce local acceptance tests

From this skill directory, use a disposable Python environment:

```bash
python3 -m venv /tmp/forensic-auditor-tests
/tmp/forensic-auditor-tests/bin/pip install -r requirements-tests.txt
/tmp/forensic-auditor-tests/bin/python -m unittest discover -s tests -v
/tmp/forensic-auditor-tests/bin/python scripts/demo_authorization.py --output /tmp/forensic-demo
/tmp/forensic-auditor-tests/bin/python scripts/validate_report.py /tmp/forensic-demo/report.json
```

The 18 tests cover wrong-row effective grants with correct Level 1/2 code, missing independent
policy, legitimate time/scoped exceptions, navigation bypass, boundary enforcement and delegation,
trust-chain configuration, assurance, generated-test evidence, safety, precedence/expiry, completion
schema gates, FSM authority, revocation, tenant reuse, duplicate side effects and tool approval binding.

Policy evidence is independently authored synthetic benchmark policy, not a real business approval.
The runtime commits to an ephemeral SQLite file; fresh connections assert status and effect counts.
This validates sequential fixture effects and contract consistency, not Oracle Forms or DB locking.
The revocation test forces a local thread after check/before write; exact client-server DB interleavings
still need a provisioned disposable DB with separate sessions. No live system is contacted.

## Scanner tests

```bash
/tmp/forensic-auditor-tests/bin/pip install semgrep==1.182.1
/tmp/forensic-auditor-tests/bin/semgrep --test references/rules/semgrep
python3 scripts/test_codeql.py
```

CodeQL CLI and language packs are separate prerequisites. Its harness exits 77 when unavailable;
otherwise it copies packs to a temporary directory, resolves dependencies, extracts local fixture
DBs, compiles/analyzes queries, and checks locations. The `.expected` files are historical outputs,
not executable qltest suites or evidence that the revised queries compile.

## Controlled Semgrep comparison

Use an unchanged baseline skill snapshot and the revised source. Both rule sets are tested against
identical revised fixture files, normalized location annotations, the same CLI and execution conditions:

```bash
PATH="/tmp/forensic-auditor-tests/bin:$PATH" python3 scripts/benchmark_semgrep.py \
  --baseline /absolute/path/to/baseline-skill --output /tmp/semgrep-comparison.json
```

The implementation run with Semgrep 1.182.1 recorded 55 true candidate locations and zero misses
for both rule sets. Baseline rules produced 3 false-positive locations; revised rules produced 0.
Candidate precision on this small authored corpus was 94.83% → 100%; recall was 100% for both.
These are synthetic candidate-location metrics, not real-world vulnerability precision/recall or
measured LLM skill improvement. Fixed false-positive classes: Java container identity treated as
raw header; overlapping TypeScript getter bindings; schema-qualified audit table exemption.
Existing test metadata also needed a valid rule ID, correct catch-clause locations and a missing
positive annotation. The original unnormalized baseline suite failed before executing its assertions.

## Model skill comparison: NOT RUN

No independent matched-model baseline/revised audit sessions were executed. This implementation
session has seen the answer key; treating it as a blind evaluator would be contaminated. Existing
`evals/evals.json` and `evals/task-success.json` remain available; passing unit tests does not establish
that a model using the revised skill discovers the planted bugs.

For a reproducible future comparison:

1. Export baseline and revised skill to separate fresh working directories, keeping repository fixtures,
   model/version, system prompt, context/tool budget and wall-clock limit identical. Do not disclose expected outputs.
2. Give both sessions the same request: “Audit the supplied synthetic repository. Follow the supplied skill.
   Report sourced invariant violations, unresolved boundaries, exact rows/paths, and durable evidence.”
3. Run the wrong-row fixture with policy, the same fixture without policy, the documented exception,
   Forms/API guard/delegation variants and specialist cases. Keep all runs local and synthetic.
4. Save transcripts and outputs. Blind-score confirmed detections, missed defects, false positives,
   policy provenance, exact row attribution, evidence classification and coverage; record actual tool calls/time.
5. Require wrong-row identification of L2-rare and independently denied clerk approval; without policy require
   NON LIQUET; documented exceptions and scoped delegation must not become findings. Compare reports using
   the schema validator plus human review of citations and execution evidence. Repeat on held-out variants.

## Compatibility and limits

The skill/package is renamed from `code-logic-auditor` to `forensic-code-auditor`. New structured
reports require schema version 1; prior Markdown-only reports must add explicit coverage and verification.
Original CodeQL IDs/pack names and existing evaluation fixtures remain for consumer continuity.
The new tenant-scope-review query emits inventory candidates even for protected code; do not count
those as confirmed vulnerabilities. RLS, custom managers, aliases, dynamic queries, actual identity
provenance and signature/guard implementations always need manual verification.

Oracle conversion, deployed DB privileges/VPD semantics, real gateway controls, client-server DB
concurrency, revised CodeQL compilation, and matched-model detection quality were NOT VERIFIED here.
No production probes, password guessing, real credential use or installed harness changes are required.
