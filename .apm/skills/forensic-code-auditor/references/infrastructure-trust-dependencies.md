# Infrastructure trust dependencies

Model firewall → gateway → Basic Auth/TLS → service account → backend/DB as a directed control graph.
For each edge record reachable networks/alternate routes, authenticated identity, delegated scope,
TLS termination, secret ownership/rotation/reuse policy, rate limits, monitoring and MFA applicability.
Use authorized sanitized configuration exports and exact deployment semantics; absent config is unknown.
Never print secrets, guess passwords or test real gateways. Basic Auth over TLS alone is not a finding.

Evaluate one credible control compromise at a time: given credential disclosure, which operations can
the connection invoke, and does independent backend authorization limit the blast radius? Distinguish
config-observed weak/shared credential policy from a measured ability to crack a password. Firewall and
gateway controls can work correctly while their shared-account backend authority violates sourced policy.
Inspect compensating scope, network restrictions, delegation and backend guards before a verdict.

Emit one primary `PERIMETER-BYPASS`/`AUTHZ-BYPASS` finding with `CONTROL-DEPENDENCY-FAILURE`
when evidence supports that chain. Record control assumptions, compromise precondition, exact config
references, protected operations and unavailable runtime evidence. Otherwise emit a conditional concern
or `NON LIQUET`, never an unconditional exploit claim.

Source-only synthetic trust configurations (`tests/fixtures/specialist-cases.json` in the skill
source checkout) include broad shared authority and a scoped backend-guarded control. Runtime-only
packages omit these fixtures. Tests inspect configuration only; no network/password testing.

For an explicit capability/edge export, run `scripts/control_dependency.py graph.json --output
WORKSPACE/control-outcomes.json` using [control-graph.json](../templates/control-graph.json).
It models each single declared control compromise and downstream capability requirements. Its outcomes
are conditional STATIC_MODEL_ONLY observations; an absent policy remains NON LIQUET. A TLS/Basic Auth
label, credential policy or syntactic backend check alone never establishes exploitable reachability.
