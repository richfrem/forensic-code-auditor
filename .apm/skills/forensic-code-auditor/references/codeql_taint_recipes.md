# CodeQL Queries: Index and Limits

Queries live in [rules/codeql/](./rules/codeql/), organized as query packs per language. They use the modern `DataFlow::ConfigSig` / `TaintTracking::Global<...>` module API (the deprecated `TaintTracking::Configuration` class API has been replaced). Historical baseline was verified with CodeQL CLI 2.27.3 against [evals/fixtures/](../evals/fixtures/).

## Query Catalog

| Query | Language | Classification | Target Invariant & Reachability |
| :--- | :--- | :--- | :--- |
| `python/UnscopedTenantLookup.ql` | Python / Django | TENANT-LEAK | Remote input (`request.GET`, route kwargs) reaching `Model.objects.get/filter` lacking tenant/org keyword scoping |
| `javascript/UnguardedStateTransition.ql` | JS / TS | FSM-BYPASS | Remote input written to `status/state/stage` property without passing a transition barrier guard |

## Execution Protocol

```bash
# 1. Create database
codeql database create db --language=python --source-root=<target_repo>

# 2. Execute analysis pack
codeql database analyze db references/rules/codeql/python --format=sarif-latest --output=codeql-report.sarif
```

## Adaptation Guidance
- Tailor the regex in `TransitionGuard` and keyword regex in `isScopingKeyword` to target codebase conventions.
- The JavaScript guard uses `DataFlow::MakeBarrierGuard`, ensuring the guarded node is sanitized strictly on the branch where the guard predicate evaluated to true.


## Revised query verification and limitations

The revised Python queries have NOT been compiled or executed in the implementation environment
(CodeQL CLI unavailable). Historical .expected files are not current qltest results. Do not infer
compilation from source inspection. Keep the original two query IDs/pack names for consumer continuity.
The added tenant-scope-review query is an inventory of unknown provenance/kwargs/raw/bulk operations,
including protected code; its hits are review work, not false confirmed vulnerabilities.

The main tenant query carries positive filter scope through receiver chains; exclude does not supply
positive scope. No user/session/auth-name barriers remain. Scope shape still does not prove trusted
identity. Assignment aliases, custom managers, dynamic kwargs, RLS and raw SQL need manual review.
The companion query inventories these boundaries rather than pretending arbitrary SQL is understood.
The JavaScript validator-name heuristic also requires manual semantic and concurrency verification.

Run `python3 scripts/test_codeql.py` from the skill directory when CodeQL is provisioned.
It creates disposable local fixture databases, compiles/runs all queries through database analyze,
and asserts the original JavaScript positives plus Python positive/negative regression locations.
Raw/bulk/kwargs/provenance review expectations are checked separately from vulnerability candidates.
Exit 77 means NOT RUN because CLI is missing. No test output is auto-blessed into .expected.

API references: [CallCfgNode](https://codeql.github.com/codeql-standard-libraries/python/semmle/python/dataflow/new/internal/DataFlowPublic.qll/type.DataFlowPublic$CallCfgNode.html)
and [getKwargs](https://codeql.github.com/codeql-standard-libraries/python/semmle/python/dataflow/new/internal/DataFlowPublic.qll/predicate.DataFlowPublic$CallCfgNode$getKwargs.0.html).
