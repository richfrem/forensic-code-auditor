# Semgrep candidate and inventory rules

The current suite has 31 IDs: the original 15 candidate rules, one nullable-Boolean authorization
candidate, and 15 INFO inventory rules. Existing IDs are stable. Each YAML/JSON-YAML rule has purpose
metadata and positive/negative annotated fixtures. `semgrep --test references/rules/semgrep` exercises
all groups; the source-only combined-corpus test also checks explicit expected locations.

Original candidates cover ambient header identity (TS/Java/PHP), C# check-then-act, fail-open handlers,
Java transaction boundaries, PHP unscoped lookups, autonomous PL/SQL DML/triggers, fail-open PL/SQL,
VPD empty predicates, NULL scope expansion, Django lost updates and floating TS mutations.

Added tests cover comment-separated THEN/RETURN, context assigned before a NULL check, package-member
autonomous DML, sibling-procedure boundaries, OUT-flag authorization, both NULL-disjunct orders and
nullable Boolean rejection patterns. Generic regexes still have nested block/comment/string limits.
An audit-looking table suffix, auth function name, direct grant or AUTHID alone is never proof of safety
or exploitability. Verify actual table purpose, evaluator/caller semantics and competing defenses.

Inventory rules cover PL/SQL units/DML/grants/roles/schedulers/external calls/context/CGI identity,
Forms trigger calls/globals/item restrictions, JDBC procedure calls, ORDS handlers, gateway routes and
CI workflow triggers/interpolations/command-file writes (`ci-workflow-privileged-trigger`). Feed their
JSON to build_operation_graph.py and account for unresolved dynamic/synonym edges. A static unit without
a recognized check is an investigation candidate, not a proven authorization bypass.

Java getRemoteUser() is container identity requiring separate deployment/proxy-origin review; it is
not a direct raw-header read. Similarly, `x-ms-client-principal` on Azure App Service Easy Auth is
platform-injected when direct origin access is blocked; disposition depends on whether the backend is
reachable outside the front end. Database-enforced RLS/VPD (`SET LOCAL` / `DBMS_SESSION.SET_CONTEXT`)
can also enforce tenant scope without ORM keyword predicates. Syntactic signature guards and verified
middleware may require different manual disposition. Cross-function transaction/ORM defenses can defeat
a local pattern hypothesis.

The previous small-corpus comparison (55 candidate locations, baseline FP=3/revised FP=0) belonged to
the earlier 15-rule implementation. It is historical and does not measure the expanded suite or blind
agent detection. See [TESTING.md](../TESTING.md) and the hardening changelog for current executed gates.
