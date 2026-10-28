# Forensic auditor hardening — 2026-10-28

Unreleased changes to `.apm/skills/forensic-code-auditor/`. Installed harness copies were not edited.
The GPT Web, Gemini source review and supplied Opus implementation prompt were reconciled into a
phased plan. Missing Opus companion documents and executable evidence were not treated as available.

## Changes by phase

1. Preserved the v1 schema/validator and original 18 acceptance tests. Added report v2 with hashed,
   bounded evidence references, unique row resolution, discovered-operation reconciliation, coverage
   and criticality checks, policy provenance, path status and actual local reproduction records.
2. Added a standard-library effective-authority engine: normalized JSON inputs, explicit inheritance,
   conflicts, NULL/default/time semantics, independent policy/exception comparison, traces, matrix,
   coverage and no-policy owner questions. Locally defined adapters/signals are documented rather
   than attributed to unavailable roadmap definitions. Differential local implementation checks exist.
3. Added bounded operation discovery/graph helpers for SQL, Python, Forms, JDBC/API/export metadata.
   Dynamic dispatch, missing exports and unknown authorization semantics remain unresolved.
4. Corrected Semgrep pattern boundaries and expanded inventory rules; preserved original IDs. Fixed
   actual CodeQL compilation/library compatibility, added locked packs, real qltests and extraction
   counts, and removed function-name trust shortcuts. Historical unverified outputs are retained
   separately as legacy claims.
5. Added source-only blind-evaluation tooling, opaque targets, separate keys, unchanged baseline
   export, matched dry-run manifests, runtime staging and contamination checks. No model evaluations
   were executed. Added an explicitly static optional control-dependency model.
6. Reworked artifact runbooks, seven-step routing, flow diagram, examples, migration and assurance
   language; removed point rewards/caps. Added pinned GitHub Actions checks. Root documentation
   remains standalone APM installation with no Crow/Raven dependency.

## Executed acceptance

Run from repository root with Python 3.11.14, Semgrep 1.182.1, CodeQL 2.23.3,
python-all 1.0.7 and javascript-all 2.6.0. Exact pins are in the skill's tools.lock.

| Check | Actual local result |
|---|---|
| `python -m unittest discover -s .apm/skills/forensic-code-auditor/tests -v` | 50 tests passed |
| `semgrep --test .apm/skills/forensic-code-auditor/references/rules/semgrep` | 30/30 groups passed |
| Combined Semgrep corpus (included in unit suite) | 99 expected locations across 38 file/rule pairs |
| Generated authority cases, 200 fixed seeds, 500 rows/depth ≥4/40 roles | With-policy detection 200/200; exception false positives 0/200; without-policy top-five inclusion 200/200 |
| `python scripts/test_codeql.py` from skill source | 5/5 real qltests passed (3 Python, 2 JavaScript), including extraction counts |
| Disposable deliberately broken scanner/query copies | Semgrep exit 2; CodeQL exit 1, both correctly fail |
| Reproduction demo + v2 validation | Valid artifact contract; assurance PARTIAL, model evidence only |
| Missing-policy demo | INSUFFICIENT_EVIDENCE; NON LIQUET |
| Baseline/revised harness readiness | Matched opaque target hashes; dry runs only; 0 model calls |
| Runtime and isolated APM-installed contamination lint | PASS for specified keys/markers |
| Isolated APM 0.33.0 installation from staged runtime | 1 skill integrated in disposable temp consumer; real harness copies untouched |
| Source authoring audit and APM package validation | PASS |
| Workflow syntax/permission check | PASS locally; GitHub Actions NOT RUN |

Raw outputs are intentionally ignored under `temp/hardening/logs/`; the review Markdown bundle includes
selected acceptance outputs. Passing structural checks does not authenticate business authority or
establish that initial discovery was exhaustive.

## Unresolved and deferred

- Two added Django `get_object_or_404` cases remain missed by the pinned taint query. The companion
  inventory lists shortcut-named calls for manual review; it does not prove their binding or safety.
- No measured blind model accuracy, production benchmark, Oracle/Forms deployment, PostgreSQL lock
  test or client/server enforcement verification was run. The SQLite demo is a disposable local model.
- The operation inventory is a bounded candidate extractor. The authority engine consumes normalized
  JSON and declared semantics; arbitrary CSV/SQL parsing and universal platform adapters are absent.
- Missing Opus audit/roadmap/gap/evaluation documents, probes, corpus and patch were not ported verbatim.
  Independent regressions cover reported mechanisms; exact E12/E14 compliance remains unverified.
- Hashes check consistency, not honest artifact authorship. The local recorder is not a network sandbox.
  Runtime labels and opt-in flags do not enforce isolation. Full source installs may include regression
  files: use staged runtime packages for lean deployment and controlled blind evaluation.
- Version remains 3.4.0, unreleased. No publication, merge or new GitHub run is claimed.
