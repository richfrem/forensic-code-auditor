# Semgrep Rules: Index and Limits

Rules live in [rules/semgrep/](./rules/semgrep/). Each `*.yaml` has a companion test fixture with `ruleid:`/`ok:` annotations.

All rules are **triage heuristics**. A hit becomes a finding only after Steps 1–7 of the forensic doctrine confirm an actual reachable path.

## Tested Rules Catalog

| Rule ID | Language | Classification | Confidence | Target Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| `plsql-autonomous-transaction-business-dml` | PL/SQL | TRANSACTION-DEMARCATION | Medium | Autonomous unit executing UPDATE/DELETE/MERGE and COMMIT |
| `plsql-autonomous-transaction-in-trigger` | PL/SQL | TRANSACTION-DEMARCATION | High | Autonomous trigger workaround for ORA-04091 mutating table |
| `csharp-check-then-act-balance` | C# | TOCTOU-RACE | Medium | `GetBalance()` followed by `Deduct()` without Serializable isolation |
| `java-requires-new-partial-commit` | Java | TRANSACTION-DEMARCATION | Low | EJB / Spring `@Transactional(REQUIRES_NEW)` partial commit |
| `java-transactional-self-invocation` | Java | TRANSACTION-DEMARCATION | Medium | Calling `@Transactional` method on `this` bypassing Spring AOP proxy |
| `php-sql-by-id-without-tenant-predicate` | PHP | TENANT-LEAK | Low | SQL query by ID lacking tenant/organization column discriminator |
| `ts-floating-mutation-promise` | TS/JS | ERROR-SWALLOW | Low | Un-awaited `save/update/delete/charge` mutation in async handler |
| `python-django-read-modify-write` | Python | LOST-UPDATE | Medium | Django ORM `get()` → field mutate → `save()` lost update race |
| `ambient-header-identity-trust` | TS/JS | PERIMETER-BYPASS | Medium | Direct extraction of identity from ambient proxy headers without signature |
| `fail-open-authorization-handler` | TS/JS | FAIL-OPEN-AUTH | High | Catch-block in authorization check returning `true` / allow |

## Execution Protocol

Run tests across all rules:
```bash
semgrep --test references/rules/semgrep
```
