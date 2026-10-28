# Authorization data integrity

Use for every discovered data-driven authorization store, not only suspected fail-open code.

1. Enumerate menu → submenu → form → trigger → package/procedure → protected operation.
   Include rarely used, hidden, disabled, alternate and legacy branches. Record dynamic targets,
   unresolved library attachments and unavailable exports in the branch-coverage ledger.
2. Inventory tables, views, synonyms, role/group mappings, grants, inheritance, exceptions,
   NULL/wildcards, defaults, overrides, effective dates, cache TTL/invalidation, policy versions,
   tenant/organization/session contexts. Record export provenance/time and exact row keys without secrets.
3. Reconstruct actual evaluator order: rule selection, precedence, deny/allow conflicts, missing rows,
   duplicate rows and errors. Never assume deny-overrides or allow-overrides. Expand effective grants
   through hierarchy and groups; retain all contributing rows and the winning rule/precedence trace.
4. Obtain an independent signed-off matrix, requirement, regulation or owner-approved policy.
   Code/current DB rows/tests cannot alone establish intended policy. If unavailable, emit
   `NON LIQUET` / `NOT_VERIFIED` for policy correctness with the missing baseline and owner question.
   An executed operation may be dynamically observed while its policy correctness remains unresolved.
5. Fill [effective-permission-matrix.csv](../templates/effective-permission-matrix.csv) for each relevant
   principal/role/resource/operation/scope/entry point/state/time. Compare intended/configured/enforced;
   cite scoped exceptions before treating a discrepancy as a violation. Unknown is not deny.
6. Examine unexpected grants, sibling differences, inherited wildcard scope, stale/duplicate/conflicting
   records, wrong org, effective dates and unreviewed privileged branches. Pinpoint the row, not merely
   the correct function reading it. Root cause: `AUTHZ-BYPASS`, tag `AUTHZ-DATA-INTEGRITY`.
7. In explicitly authorized disposable local fixtures, replay intended-denied and intended-allowed cases
   through evaluator and operation. Assert committed rows, audit/queue ledger and external effects.
   Report runtime as NOT VERIFIED if no faithful local runtime/data is available; never use live probes.

Required artifacts: navigation graph; data-source inventory; effective-permission matrix;
intended/configured/enforced diff; branch-coverage ledger; unresolved-policy questions.
Use [cross-entrypoint authorization](cross-entrypoint-authorization.md) for every operation with multiple callers.
The synthetic wrong-row fixture lives in [policy.json](../tests/fixtures/authorization/policy.json),
[configuration.json](../tests/fixtures/authorization/configuration.json) and [runtime.py](../tests/fixtures/authorization/runtime.py).
It models correct Level 1/2 evaluation with erroneous row L2-rare; it does not validate Oracle semantics.
