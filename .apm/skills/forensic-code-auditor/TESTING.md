# Testing, evidence and benchmark boundaries

## Contents

- [Local commands](#local-commands)
- [What the tests establish](#what-the-tests-establish)
- [Blind evaluation](#blind-evaluation)
- [Compatibility and remaining limits](#compatibility-and-remaining-limits)

## Local commands

Run from this source skill directory. Use Python 3.11.14 for CodeQL extraction and the exact
versions in [tools.lock](tools.lock). Keep environments/results under ignored temp/ paths.

```bash
python3 -m venv WORKSPACE/venv
WORKSPACE/venv/bin/pip install -r requirements-tests.txt
WORKSPACE/venv/bin/python -m unittest discover -s tests -v
WORKSPACE/venv/bin/semgrep --test references/rules/semgrep
python3 scripts/demo_authorization.py --output WORKSPACE/demo
python3 scripts/validate_report.py WORKSPACE/demo/report.json --evidence-root WORKSPACE/demo
python3 scripts/demo_authorization.py --without-policy --output WORKSPACE/no-policy
python3 scripts/test_codeql.py
```

CodeQL CLI 2.23.3 is separate from pip. Put it and Python 3.11 on PATH. The harness copies packs
to a disposable directory, installs their pinned/locked libraries and runs five real qltests,
including extraction-count queries that must each find one expected source file. It never silently
accepts new output. New .expected files were generated from actual executions after inspecting
candidate locations. Root historical .expected outputs were retired; original query IDs/pack names
are preserved. A missing CLI exits 77 (NOT RUN); a wrong tool version fails, not passes.

## What the tests establish

- V1 regression tests preserve the prior model/contract under validate_report_v1.py. They are legacy
  structural checks, not v2 assurance or blind evaluation.
- V2 tests check evidence files, hashes, lines/rows, traversal/symlink containment, candidate omissions,
  criticality, false absence, policy provenance classes, unexecuted/fake evidence and scanner failures.
- Actual local run records capture reviewed scripts, command/versions/times and stdout/stderr hashes.
  The demo uses a file-backed disposable SQLite model, commits, then reads state/effects through a
  fresh connection. It discovers rows through the engine, with no expected row key in the demo.
- The engine checks explicit inheritance/conflict/NULL/default/date/exception semantics. Over the
  controlled 200-seed generator (500 rows, hierarchy depth ≥4, 40 roles), the implementation observed
  200/200 injected rows with policy, 0/200 exception false positives and 200/200 top-five owner-question
  inclusion without policy. These are fixture-distribution measurements; no policy-free anomaly is a
  confirmed violation and no real-world recall is implied. Renaming/moving rows has separate tests.
- Thirty Semgrep candidate/inventory rule groups have paired annotated fixtures. A second test scans
  all rules against the combined corpus and compares 99 explicit location expectations across 38
  file/rule pairs. The PL/SQL behavioral package's comment and assigned-context cases are included.
- Python CodeQL has seven attributed tenant candidates on its regression fixture; the scope-review
  query deliberately also flags protected sites for provenance review. JavaScript candidates include
  named guards, no-op/enum-only guards, setters, bulk bodies and raw SQL inputs. Candidate hits are
  not confirmed vulnerabilities. Unknown identity/guard semantics remain manual work.

No test here certifies honest authorship of artifacts, independent business approval, full repository
discovery or real Oracle/PostgreSQL locking semantics. Hashes detect changed references, not malicious
replacement of a report plus all its evidence. The local recorder is not a sandbox.

The [agent runtime threat reference](references/agent-runtime-threats.md) supplies manual discovery,
source-to-effect tracing and proposed paired cases for metadata injection, dormant behavior,
delegation, memory and audit boundaries. It does not add automated detectors. A deterministic mock
of a model's tool choice tests the mock; live model resistance, hidden-trigger coverage and detection
accuracy require separately authorized behavioral evaluations. Local POC reports are research inputs,
not independently reproduced results for this skill.

## Blind evaluation

Scored targets/keys must be generated outside the deployed skill, under ignored temp/evals-private/.
Maintained source tests and labeled worked examples are not blind accuracy evidence. Generate isolated
vulnerable, protected and missing-policy targets with opaque IDs. Do not show the agent the answer
keys, generator source, other variants, expected files or test code.

```bash
python3 tests/run_blind_eval.py --seed 1701 --variant vulnerable --output WORKSPACE/evals-private \
  --skill-source BASELINE_OR_REVISED_SKILL --command-json '["agent", "{skill}", "{target}"]'
```

Default is dry-run; no model command runs. Actual execution requires --execute, --allow-model-run and
--sandbox-configured after maintainer authorization. These flags do not create a sandbox: the selected
agent/provider must enforce visibility. Working directory alone cannot hide sibling keys.

The harness accepts an unchanged baseline source exported from commit
`c7cb05da831a6eac78993193d94a95753bd29306` or the revised source. For a matched comparison keep model,
version, prompt, context/time/tool budgets and allowed source visibility identical; record actual
outputs. The supplied scorer separates attributed detections, protected false positives and missing-
policy calibration, and still needs human evidence adjudication. Paid/blind model runs have NOT RUN.

Positive credit in every variant requires both the expected operation and contributing row. An
unrelated REFUTED or NON LIQUET finding earns no defense/calibration credit. Schema-v2 defenses
require declared `proof` and `STATIC_PROVEN` or `DYNAMIC_REPRODUCED` verification; legacy evaluation
reports use `defense_ref`. Any CONFIRMED/SUSPECTED finding still counts as a protected-target false
positive and prevents missing-policy calibration, including findings outside the expected operation.
These counters do not validate artifacts or establish that the submitted reasoning is sound: validate
canonical reports and adjudicate evidence separately. Unknown target variants are errors. Scorer
changes require a fresh matched baseline; scores from different scorer versions are not comparable.

Runtime-only staging is available via `scripts/stage_package.py --output WORKSPACE/runtime-skill`;
check it with `scripts/contamination_lint.py --package-root WORKSPACE/runtime-skill --sealed-keys WORKSPACE/evals-private/keys`.
The lint checks specified IDs/markers, not every possible semantic leak. Stage excludes source-only
regressions/evals and qltests. Direct installation of a development checkout may include its source
regression files; use the staged runtime for controlled blind runs and lean deployment packages.

## Compatibility and remaining limits

Schema v2 replaces unverified policy booleans with explicit basis classes, and requires structured
artifact references/discovery coverage. Existing reports use validate_report_v1.py and the retained
v1 schema; migrate to v2 rather than interpreting a v1 pass as v2 evidence verification.

Original seven steps, evidence levels, specialist procedures and scanner identifiers remain. Point
scores and uncertainty caps are removed. The runtime label can describe local Docker/PG/Oracle while
the recorder opt-in remains isolated-local-synthetic; this is a safety declaration, not isolation proof.

The missing Opus roadmap/probe files were not ported verbatim. Equivalent regressions and explicitly
documented local semantics were implemented from the supplied prompt. The generic six anomaly signals
and three hierarchy adapters are not claimed as its absent exact definitions. Differential evaluator
checks and control-dependency outputs are declared models requiring reviewed local inputs.

Oracle Forms binary extraction, exact AUTHID/VPD behavior, client-server concurrency and runtime-only
configuration remain NOT VERIFIED. Dynamic SQL/synonyms, nested/overloaded PL/SQL and custom helper/
manager behavior remain known candidate-extraction limits. CI configuration is supplied; only an actual
GitHub Actions run establishes remote CI status. Raw commands/results are recorded in the root hardening
changelog, with transient logs under temp/. No production or shared-system test is authorized.

Known regression boundary: the pinned Python taint query currently misses the two added
`get_object_or_404` unscoped/attacker-scope cases. The companion inventory query lists all
three shortcut variants for manual review. Passing qltests preserves these observed outputs;
it does not claim those two taint detections succeeded.

## GitHub configuration collector

`tests/test_github_collector.py` uses mocked CLI responses to check fixed GET authority, encoded
paths, pagination, access denial, timeouts, malformed output and refusal to overwrite evidence.
These tests do not establish live GitHub configuration, cloud access or resistance to prompt injection.
Use [GitHub scanner security](references/github-ai-scanner-security.md) for collection scope and limits.
