# Cross-entry-point authorization

Start at high-impact state-changing sinks and enumerate reachable callers backward: Forms/menu and
triggers, PL/SQL packages, direct DB grants, REST/SOAP APIs, gateway, queue consumers, batch,
MCP tools, scheduler, privileged maintenance. Trace interfaces forward to find overlooked sinks.
List dynamic/unavailable edges explicitly rather than calling a partial graph exhaustive.

For every path record originating principal, authenticated identity, delegated authority,
tenant/org scope, session/package state, DB connection identity, policy source/version,
actual check location, transaction and recheck at the operation boundary. Include durable outcome evidence.
Build a caller graph and path enforcement map keyed by operation; explain authorized differences.
Equivalent intended decisions do not require identical code. Service accounts may act under explicit,
scoped delegation; neither an API label nor absence of a UI guard establishes a violation.

Evaluate compound chain: correct menu check → incorrect Level 2 row → procedure assumes navigation →
gateway shared account directly invokes procedure. Establish reachability and policy for each edge,
then report one interacting failure with primary category and mechanism tags. Inspect compensating
backend guards, connection privileges and verified delegation before confirming.

Required artifacts: protected-operation inventory, caller graph, enforcement map, decision matrix,
policy equivalence/difference rationale and durable effect evidence. Missing policy/path information
stays unresolved under the canonical completion contract. A screen being hidden establishes only
UI discoverability; it does not prove operation authorization.
