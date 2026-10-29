# Forensic audit execution contract

## Contents

- [Verdict contract](#verdict-contract)
- [Phases and the seven-step method](#phases-and-the-seven-step-method)
- [Routing](#routing)
- [Structured reports and evidence](#structured-reports-and-evidence)
- [Safety and limits](#safety-and-limits)

## Verdict contract

**Evidence:** `CONFIRMED` | `SUSPECTED` | `NON LIQUET` | `REFUTED`

**Verification:** `STATIC_PROVEN` | `DYNAMIC_REPRODUCED` | `TEST_GENERATED` | `NOT_VERIFIED`

**Severity:** `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`

**Assurance:** `VERIFIED_SCOPE` | `PARTIAL` | `INSUFFICIENT_EVIDENCE` | `NOT_ASSESSED`

**Conclusion:** `FINDINGS_REPORTED` | `NO_FINDINGS_IN_VERIFIED_SCOPE` | `INCONCLUSIVE` | `NOT_ASSESSED`

CONFIRMED requires sufficient, reachable static proof or an actually executed reproduction with
verified durable observations. REFUTED requires evidence that the relevant defense defeats the
hypothesis. Generated tests alone establish neither. SUSPECTED names the established mechanism and
unverified prerequisites; NON LIQUET supplies competing models and the exact evidence needed.
No point rewards or uncertainty caps apply. Quantity of confirmed findings is not a success metric.

Do not flag the absence of a preferred implementation when a verified alternative enforces the sourced property.

Source an invariant from a business requirement, schema constraint or authoritative API contract.
For intended authorization policy, code, current permission rows and tests are corroboration rather
than independent authority. Owner-approved policy, regulation, requirements or contracts must support
CONFIRMED/SUSPECTED authorization-policy claims. Missing/conflicting policy yields NON LIQUET;
an unusual row or peer anomaly is an owner question, not an invented violation.

| Impact / reachability | High | Medium | Low |
|---|---|---|---|
| High impact | CRITICAL | HIGH | MEDIUM |
| Medium impact | HIGH | MEDIUM | LOW |
| Low impact | MEDIUM | LOW | LOW |

Keep severity separate from certainty and coverage. Calculate severity from justified impact and
reachability, not confidence. A reviewed scope may contain vulnerabilities. An unresolved finding,
deferred candidate, unsupported source, assumed semantics or inaccessible critical boundary prevents
an unqualified verified/clean conclusion. Never claim the whole system is SECURE/PASS.

Treat software as state machines bounded by resource, informational and runtime constraints. Vendor
certifications, tradition, common patterns and clean scanner output do not prove safety. Official
platform specifications may establish mechanics, but verify that the target actually uses them.

## Phases and the seven-step method

The original Step 0 plus seven steps remain mandatory; phases group their artifacts rather than
replace the reasoning procedure.

| Phase | Steps | Required output and exit criterion |
|---|---|---|
| 0: Discovery | Step 0: Scope and triage | Persist candidate inventory and source snapshot before conditional routing; list unsupported/dynamic/excluded paths. Rank value movement, lifecycle mutation, tenant access, then reads. |
| 1: Reconstruction | Step 1: Observed facts; Step 2: Hard boundary conditions | Exact source/row references, callers, identities, transactions, isolation, locks and effects. Missing exports remain explicit. |
| 2: Alternatives | Step 3: Competing reconstructions; Step 4: Degradation and obfuscation correction | Intended/adversarial paths, verified defenses, exception/fallback behavior and discriminating hypotheses. |
| 3: Authority and failure | Step 5: Incentive and trust dynamics; Step 6: Failure point mapping | Caller-controlled inputs, delegated scope, exact failure point and primary category with mechanism tags. No duplicate findings for one compound chain. |
| 4: Proof and reporting | Step 7: Discriminating tests and proof | Static trace or run record, durable-state/effect assertions, artifact validation and reconciled coverage of every discovered candidate. |

For each selected protected operation complete or mark unresolved all nine dossier items:
invariant, entry points, policy provenance, execution trace, competing defenses, failure hypothesis,
discriminating proof, classification and coverage. Unresolved items identify the needed evidence;
a deferred operation identifies its reason and caps assurance. Do not let an unreviewed candidate
disappear when context is compressed or analysis is delegated.

## Routing

Run lightweight discovery first. Candidate extraction is bounded and is never an exhaustive denominator
for languages/features it cannot resolve. Unknown surfaces must survive into the report. For developer
tooling, inventory installation, configuration, hooks, credentialed execution and release writes as
protected operations; prioritize transitions into stronger authority. Route CI/release paths through
the [CI/release authority prompt](references/prompts/ci_release_trust_audit.md).

| Discovered surface | Reference | Tool | Artifact |
|---|---|---|---|
| State-changing procedures/routes and alternate callers | [Cross-entrypoint authorization](references/cross-entrypoint-authorization.md) | `inventory_sinks.py`, `build_operation_graph.py` | `operations.json` |
| Permission stores, wrong effective rows or obscure menu branches | [Authorization data integrity](references/authorization-data-integrity.md) | `authz_effective.py` | `matrix.csv`, `coverage.json`, `diff.json`, `owner_questions.json` |
| Legacy Forms/database authority | [Forms/PLSQL](references/prompts/legacy_forms_authorization_audit.md) | Inventory rules plus authorized exports | Navigation/caller graph and unknown bindings |
| Firewall/gateway/shared account dependencies | [Infrastructure trust](references/infrastructure-trust-dependencies.md) | Configured control graph when supplied | Trust edges, compromise assumptions and scoped effects |
| Concurrency/revocation | [TOCTOU](references/prompts/concurrency_toctou_audit.md) | Reviewed local reproduction with a post-check hook | Interleaving trace and durable ledger |
| Workflow/tenant/replay/tool boundaries | Relevant [inspection prompt](references/prompts/) | Candidate rules and discriminating tests | Operation dossier and effect evidence |

Classify with the existing [taxonomy](references/logic_invariants_taxonomy.md). Semgrep and CodeQL
outputs remain candidates, including protected code requiring defense review. Preserve tool versions,
exit codes and outputs; a failed scanner is not a zero-hit scan.

## Structured reports and evidence

Schema v2 is canonical: [report.schema.json](templates/report.schema.json). Markdown finding sections
are a readable rendering of the same report: use identical enum casing. Reconcile counts and
refuted/unresolved dispositions across the Markdown, JSON and any SARIF. For maintainer delivery,
include the evidence needed to reproduce and fix each finding without local issue files; follow
the [GHAS completion checks](references/ghas-security-reporting.md) for submission metadata. NON LIQUET is a finding with
`obstruction_mechanism`, `candidate_models`, `telemetry_spec` and unresolved prerequisites; relevant
obstructions include MISSING-POLICY and MISSING-EXPORT. Hypothetical severity describes conditional
impact and does not establish a vulnerability. Source and artifact references are structured objects
with relative path, SHA-256 and optional line range or CSV/JSON row key.

Run from the skill directory, keeping output under an ignored workspace such as `temp/`:

```bash
python3 scripts/build_operation_graph.py --source-root TARGET --evidence-root WORKSPACE --output WORKSPACE/operations.json
python3 scripts/authz_effective.py --config WORKSPACE/configuration.json --policy WORKSPACE/policy.json --output WORKSPACE
python3 scripts/run_repro.py --evidence-root WORKSPACE --environment isolated-local-synthetic --runtime isolated-local-postgres -- python3 reproduce.py
python3 scripts/validate_report.py WORKSPACE/report.json --evidence-root WORKSPACE
```

Only use explicitly sourced evaluator adapters. NULL/wildcard meanings, inheritance, defaults,
conflict precedence and acceptance-time vs execution-time authority are application-specific. A
modeled grant is not runtime-enforced behavior. Differential checks can compare a reviewed local
evaluator, but do not execute imported SQL or untrusted application code to load policy exports.

V2 checks reference existence/integrity, source locations, declared categories, discovered candidate
accounting and proof metadata. It cannot certify policy authority, truth of static reasoning, honest
initial discovery, or evidence authenticity against an author who can replace all artifacts/hashes.
A valid run record binds reviewed code and captured observations; inspect the assertions themselves.
Legacy `validate_report_v1.py` remains available for schema-v1 compatibility and is structural only.

## Safety and limits

All behavioral tests require explicitly authorized local, disposable resources with synthetic data.
Never probe production, shared staging, real enterprise databases or gateways; never guess passwords
or disclose credentials. Authorized sanitized configuration exports may be inspected offline.
Rollback alone is not isolation: autonomous commits and external effects can survive it.

`run_repro.py` is a recorder for reviewed local Python tests, not a network/process sandbox. Its
argument filters and opt-in label do not stop network calls made by executed code. Use independently
enforced isolation for untrusted code; otherwise remain static/NOT VERIFIED. Bound waits and capture
errors. Concurrent starts alone do not force the relevant interleaving. SQLite is suitable for
sequential committed-state models, not Oracle/PostgreSQL lock-equivalence claims.

On missing context, continue useful read-only work and record uncertainty rather than silently
assuming a defense or a flaw. Local fixture tests, candidate-rule accuracy, validator integrity and
blind agent discovery are different measurements. Model runs require separate authorization and
matched tool/context/time budgets. [TESTING.md](TESTING.md) records actual gates and remaining limits.
