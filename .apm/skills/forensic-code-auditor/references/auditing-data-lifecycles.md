# Data lineage and lifecycle runbook

## Contents

- [Scope and discovery](#scope-and-discovery)
- [Reconstruct copies and authority](#reconstruct-copies-and-authority)
- [Discriminating proof and coverage](#discriminating-proof-and-coverage)

## Scope and discovery

Use for discovered caches, search/index/embedding stores, reports, object links, exports, backups,
imports, migrations, deletion and restore paths. Apply [the contract](../instructions.md) and
[tenant context](prompts/multi-tenant-context-audit.md). A tenant column or deletion endpoint does
not establish isolation or completion. Source the exact access, retention or revocation guarantee;
an undocumented preference is not an invented invariant.

## Reconstruct copies and authority

1. Select a protected record and trace primary write → derived copies → readers → deletion → restore.
   Record each writer/reader, tenant/owner, namespace, ACL version, retention rule, invalidation owner
   and queued work. Include previews, logs, diagnostics, analytics, replicas and support snapshots.
   Missing external storage policy remains an unavailable edge.
2. Compare primary queries with raw/bypass clients, relations, aggregates, cache/search retrieval and
   background jobs. Trace namespace collisions in keys, object paths, uniqueness and deduplication.
   A protected primary read does not establish that its cached or exported copy is protected.
3. Reconstruct ACL/membership changes, soft delete, tombstones, consent withdrawal and account switch.
   Determine whether old subscriptions, signed links, exports and queued jobs retain authority under
   sourced policy. Record allowed propagation delays rather than assuming immediate revocation.
4. Trace export selection, per-item/field filtering, artifact storage and final download authority.
   For imports/restores, check current owner, scope, schema and lifecycle rules at the resulting write.
   Authentic backup bytes do not independently authorize their restoration into the current tenant.
5. Inspect backfill, dual reads/writes, old-record defaults, rollback and resumed migrations. Compare
   mixed-version readers and writers. Track whether restore reinstates revoked grants, deleted data
   or stale credentials and whether later queued work recreates removed state.
6. For counts, ordering, errors or uniqueness oracles, identify the confidential predicate and the
   lower-trust observer. Public identifiers or ordinary response variance alone establish no leak.

## Discriminating proof and coverage

Use explicitly authorized disposable local resources and synthetic tenants only. Pair allowed and
denied reads/writes through the same copy paths; repeat after ACL change, deletion, account switch
and restore. Force queued work before and after the lifecycle change. Assert committed primary state,
derived copies, download authorization and mock effects; an HTTP success or missing primary row alone
does not prove completion. Do not execute imported applications or backup scripts to inspect exports.

Attach a copy/reader graph, sourced timing guarantees, per-path decisions and unavailable stores to
the nine-item dossier. Classify the actual breach under the existing taxonomy, commonly TENANT-LEAK,
AUTHZ-BYPASS or FSM-BYPASS. Missing retention policy, external ACLs or invalidation semantics yield
bounded uncertainty. This runbook adds manual procedures, not automated lineage or deletion checks.
