# CodeQL candidates and executed qltests

Two packs contain three queries, with pinned libraries/lockfiles and five actual qltests:

| Query | Purpose | Tested boundary |
|---|---|---|
| Python UnscopedTenantLookup | Candidate discovery | Request-tainted unscoped/attacker-scoped Django lookup, chains, kwargs and mutation inputs |
| Python TenantScopeReview | Inventory | Scope provenance, raw/bulk and opaque operations, including protected code |
| JavaScript UnguardedStateTransition | Candidate discovery | Direct state writes, setters, Object.assign, body update payloads and SQL inputs |

Use CodeQL 2.23.3, Python 3.11.14, python-all 1.0.7 and javascript-all 2.6.0. The original ^1.x JS
pin did not support the modular API. Original query IDs and pack names stay stable. Run
`python3 scripts/test_codeql.py`; it uses actual `.qlref`/`.expected` suites and extraction-count
checks. Expectations were generated after compiling/executing queries and checking actual locations.
No CLI means NOT RUN, not successful validation. A compilation or extraction failure fails the gate.

Python positive filter shape can flow through a receiver chain; exclude is not positive scope.
No user/session/auth-name barrier supplies trusted identity. Custom managers, Q objects, aliases,
RLS/VPD, expanded kwargs and ORM-specific models require manual review; the inventory query does not
pretend to parse arbitrary SQL or prove principal binding.

The JavaScript query deliberately does not sanitize a value because a function is called canTransition
or validateState. Protected handlers can be candidates too: inspect actual edge/actor policy, aliasing,
atomicity and storage defenses before a finding. Two arguments or a method name alone are insufficient.
Raw SQL/setter candidates can include unrelated work; retain this false-positive class explicitly.

Candidate precision is not vulnerability precision. Clean query output does not establish complete
operation discovery or safety. See [TESTING.md](../TESTING.md) for actual counts and evaluation limits.

Known regression boundary: the pinned Python taint query currently misses the two added
`get_object_or_404` unscoped/attacker-scope cases. The companion inventory query lists all
three shortcut variants for manual review. Passing qltests preserves these observed outputs;
it does not claim those two taint detections succeeded.
