# Message and stream authority runbook

## Contents

- [Scope and discovery](#scope-and-discovery)
- [Reconstruct interpretation and authority](#reconstruct-interpretation-and-authority)
- [Discriminating proof and coverage](#discriminating-proof-and-coverage)

## Scope and discovery

Use for discovered RPC, streaming, subscriptions, broker/queue, webhook, callback and event-bus paths.
Apply [the contract](../instructions.md), [operation paths](cross-entrypoint-authorization.md) and
[replay](prompts/idempotency-replay-audit.md). Schema validity and an authenticated channel establish
neither per-resource authority nor intended ordering. Obtain authorized configuration exports for
external ACLs and delivery guarantees; do not contact brokers or providers to fill missing evidence.

## Reconstruct interpretation and authority

1. Trace producer → transport/broker → converter/gateway → consumer → storage/effects. Record each
   authenticated peer, delegated application principal, tenant, event type/version, route, namespace,
   check location and effect. Include compatibility, reflection, health, retry and dead-letter paths.
2. Compare authoritative envelope fields with body tenant/account/subject/resource fields. Establish
   who can write each and which value the authorization check and handler actually consume. Workload
   credentials do not independently authorize a message to impersonate any application principal.
3. Compare parser/converter representations: duplicate/unknown fields, union/enum defaults, numeric
   widths, encoding, normalization and old/new schemas. A disagreement claim requires two concrete
   interpretations and a security-relevant difference reaching the operation, not malformed input alone.
4. Trace interceptor registration across unary, stream, gateway and alternate methods. For each item,
   batch or subscription, inspect resource changes, membership revocation and connection reuse. Source
   whether acceptance-time authority remains valid or execution-time revalidation is required.
5. Bind replies, callbacks, cancellations and acknowledgments to the outstanding request's peer,
   principal, tenant, operation and lifecycle. Inspect request-ID reuse, reconnects and stale replies.
   Namespace/topic/wildcard/consumer-group selection must match independently intended scope.
6. Establish delivery, acknowledgment, commit, deduplication and ordering semantics separately. Follow
   old events after revocation, restored queues, partial multi-consumer transitions and crash/retry
   windows. Inspect diagnostic and dead-letter readers as alternate disclosure paths.

## Discriminating proof and coverage

Use explicitly authorized local synthetic producers/consumers or an in-memory transport. Pair allowed
and denied peers; vary envelope/body identity, one stream item, schema version, reply correlation,
duplicate delivery and order. Force the relevant interleaving and assert committed state plus queued/
external mock effects. A simulated broker establishes only the declared delivery model; do not claim
actual broker ACLs, mesh attachments or provider-signature behavior without applicable evidence.

Attach message/identity lineage, competing interpretations, delivery semantics and missing routes to
the nine-item dossier. Use the existing AUTHZ-BYPASS, TENANT-LEAK, REPLAY-IDEMPOTENCY, FSM-BYPASS or
DUAL-WRITE category according to the breached invariant. Unavailable peer identity, broker ACLs or
schema compatibility remain precise unresolved prerequisites, not presumed absence of controls.
