# Operation paths and coverage runbook

Start at high-impact state-changing sinks and trace callers backward, then trace interfaces forward
to find missed sinks. Persist candidates independently of findings before selecting specialist prompts.

1. Run the INFO Semgrep inventory rules on authorized source/exports and save JSON. Then run:
   `python3 scripts/build_operation_graph.py --source-root TARGET --evidence-root WORKSPACE --semgrep-json scan.json --exports bindings.json --output WORKSPACE/operations.json`.
   The same bounded extractor is available as `inventory_sinks.py`. It handles narrow SQL/Python AST,
   Forms-export and direct JDBC/API call patterns; nested/overloaded PL/SQL, imports, reflection,
   dynamic SQL, synonyms and binary Forms modules need manual resolution and remain listed limitations.
2. Supplement candidates from sanitized menu/library, GRANT EXECUTE/role/direct-DML, scheduler,
   DB-link, ORDS, gateway, queue, batch, maintenance and MCP exports. A missing detector/hit does not
   establish absence. Record exclusions and source hashes; a manifest hash is not completeness proof.
3. For each operation map all known paths: originating principal, authenticated/delegated identity,
   tenant/org/session/package state, connection identity, policy source/version, check location,
   transaction and effects. Supplemental connection mappings are declared exports until corroborated.
   Record direct static edges with evidence and unresolved/assumed edges explicitly.
4. Compare intended decisions and actual guards at each path. Different interfaces can implement
   equivalent authority; legitimate scoped delegation is a defense. Gateway authentication is not
   sufficient business authority, and a service account is not automatically escalation. A recognized
   assertion name or SYS_CONTEXT call does not prove trusted identity or correct policy evaluation.
5. Join effective-grant rows and per-path checks on the same protected operation. Report an interacting
   failure once, with primary category and mechanism tags; independently substantiate each contributing
   row, caller, authority transfer and durable outcome. Hidden UI controls establish discoverability only.
6. Reconcile every operations.json candidate with a complete dossier or deferred reason. V2 validation
   rejects omitted operations and false absence, and unresolved critical paths cap assurance. If a static
   unit has no recognized authz call, `authz_check: none` describes the inspected body only; external
   middleware/grants/triggers and delegated authority are still competing defenses to examine.

Artifacts: operations.json caller/entry graph, effective permission matrix, per-path decision rationale,
source/export provenance and durable observations. Observed runtime behavior stays separate from static
configuration models. Read [the contract](../instructions.md) for proof, evidence and assurance gates.
