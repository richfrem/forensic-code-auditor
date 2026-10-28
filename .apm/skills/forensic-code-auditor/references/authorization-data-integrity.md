# Authorization data integrity runbook

Use for every discovered data-driven authorization store, including correct code consuming a wrong
permission row. Current rows/tests are not independent authority for intended policy.

1. Obtain authorized offline navigation, role/group, grants, scope/date and policy exports. Record
   table/view/synonym names, export time/version, cache behavior and exact row keys without secrets.
   Expand menu → submenu → form → trigger → procedure → operation, including hidden/disabled/legacy
   branches. Missing exports and dynamic bindings remain unresolved.
2. Establish the application's actual evaluator semantics and provenance. Normalize nodes, rows,
   role inheritance, principals, scope/state/time domains and known entry paths into JSON. Each
   semantics key carries `source_ref` or ASSUMED. The current helper supports leaf_only, nearest and
   union hierarchy adapters; priority/specificity selection; deny/allow/unknown conflicts; explicit
   NULL-scope meaning and defaults. These are declared models, never universal Oracle semantics.
3. Run `python3 scripts/authz_effective.py --config configuration.json --policy policy.json --output WORKSPACE`.
   Omit --policy when unavailable. Read `matrix.csv`, `coverage.json`, `diff.json`,
   `owner_questions.json` and `anomaly_signals.json`. Compare every declared role/resource/scope/path/
   state/time combination. Keep all matched/winning rows and precedence; cycle/dangling/oversized
   inputs fail explicitly. The row ratio counts inspected exports, not proven permission correctness.
4. Independently source intended policy from approved owner requirements, regulation, contracts or
   signed-off matrices. Honor scoped/time-limited exceptions. Closed-world denial is allowed only
   when policy explicitly declares it; open-world absence remains unknown. Contradictory policy also
   remains unknown. No baseline means owner questions; a peer anomaly is never a confirmed violation.
5. Inspect unexpected grants, inherited/wildcard expansion, conflicting/inactive records, scope errors
   and path differences. The engine's six generic anomaly signals are prompts for review: privileged
   peer outlier, inherited grant, wildcard expansion, conflicting grants, inactive rule and cross-entry
   divergence. SoD constraints are separately sourced review signals. Rank measurements apply only
   to the tested synthetic distribution and do not establish intent without policy.
6. Distinguish incorrect configuration from incorrect evaluator semantics and runtime enforcement.
   `modeled_path_decision` is declared behavior; `enforced` stays unknown without actual observation.
   Use optional --differential only with a reviewed local evaluator command. Never execute imported SQL
   or an unknown application to read its policy data.
7. Join [operation paths](cross-entrypoint-authorization.md) before synthesizing findings. For dynamic
   proof, use a disposable local model/test DB, independently sourced allowed/denied principals and
   fresh-connection status plus audit/outbox/external mock ledgers. Record execution using run_repro.py.
   Without the actual supported Oracle runtime, AUTHID/VPD behavior remains NOT VERIFIED.

Required artifacts: navigation graph; source/export inventory; effective matrix; intended/configured/
observed diff; candidate coverage and owner questions. Assumed semantics, incomplete domains and unknown
branches cap assurance. The [worked example](../examples/configuration.json) demonstrates the input
format; it is not a blind benchmark or an authoritative policy for another application.
