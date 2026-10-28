# Inspection Prompt: Multi-Tenant Context Isolation Audit

> [!IMPORTANT]
> **Governing Doctrine**: All inspections are governed by `instructions.md` (First-Principles Epistemology, Invariant Sourcing, and Four Evidence Levels). The criteria below are investigative prompts, NOT rigid checklist constraints. Accept verified alternative enforcement mechanisms (e.g. PostgreSQL Row-Level Security, schema-per-tenant isolation, cryptographically partitioned caches) if the isolation invariant is demonstrably maintained.

Execute this inspection to evaluate tenant boundaries, authorization context propagation, and cross-tenant leakage.

## 1. Context Lifecycle Tracking & Invariant Sourcing
- Identify the explicit tenant isolation model specified by the architecture:
  - Application-level predicate enforcement (`WHERE tenant_id = :id`).
  - Database-level isolation (PostgreSQL Row-Level Security / RLS policies).
  - Schema-per-tenant or database-per-tenant physical separation.
  - ORM-managed querysets anchored to the authenticated principal (`request.user.tenant.documents.all()`).
- Trace how `tenant_id` / `org_id` / `user_id` enters the request pipeline.
- Verify whether tenant identity is extracted from a verified cryptographic session/token or if it can be supplied via user-controlled body/query parameters (IDOR).
- Check context propagation across background threads, workers, and asynchronous tasks (`asyncio.create_task`, Celery tasks, SQS messages).

## 2. Invariant Checklist
- [ ] **Scoping Enforcement**: Does every query, filter, aggregation, and delete operation restrict access to the active tenant through either an explicit query predicate, an ORM scoped manager, or a verified database RLS policy?
- [ ] **Cache Key Namespacing & Partitioning**: Are shared caching layers (Redis, Memcached) partitioned per-tenant (via key prefix, database index, or tenant tag) to prevent cache pollution across organizational boundaries?
- [ ] **IDOR / Object ID References**: Can an authenticated attacker pass an arbitrary ID belonging to another organization to view or mutate state?
- [ ] **Bulk / Batch Operations**: Do batch update/delete APIs verify that *every* item in the target list belongs to the authenticated tenant before mutation?

## 3. Discriminating Test Vector
```python
def test_cross_tenant_access_blocked():
    tenant_a_doc = create_document(tenant_id="tenant-A")
    client_b = authenticated_client(tenant_id="tenant-B")
    
    # Sourced Invariant: Tenant B must never read Tenant A's documents
    response = client_b.get(f"/api/v1/documents/{tenant_a_doc.id}")
    assert response.status_code in [403, 404], f"Cross-tenant leak detected: {response.status_code}"
```


## 4. Trusted provenance and reused sessions
Trace HTTP/proxy identity through Oracle/PG session context setters, connection-pool checkout,
release/reset on success and exception, async task serialization, caches, ORM managers and bypass roles.
Presence of a tenant_id predicate does not prove that its value belongs to the authenticated principal.
Inventory unknown provenance, **kwargs, raw SQL and bulk writes even if no taint path is found.
Test A checks out/returns a connection, B reuses it with missing context, then A/B with a valid context;
assert durable tenant-specific writes and absence of cross-tenant/queued effects. An unset context must
follow sourced policy; inspect RLS/VPD and privileged bypass grants rather than assume ORM protection.
The HTTP example above also needs persisted-state and external-effect assertions for mutation paths.
