# Inspection Prompt: Multi-Tenant Context Isolation Audit

Execute this inspection to evaluate tenant boundaries, authorization context propagation, and cross-tenant leakage.

## 1. Context Lifecycle Tracking
- Trace how `tenant_id` / `org_id` / `user_id` enters the request pipeline.
- Verify whether tenant identity is extracted from a verified token/session or if it can be supplied via user-controlled body/query parameters.
- Check context propagation across background threads, workers, and asynchronous tasks (`asyncio.create_task`, Celery tasks, SQS messages).

## 2. Invariant Checklist
- [ ] **Predicate Enforcement**: Every query, filter, aggregation, and delete operation explicitly includes the active tenant ID.
- [ ] **Cache Key Namespacing**: Are Redis/Memcached keys strictly prefixed with `tenant:{tenant_id}:` to prevent cache pollution across tenants?
- [ ] **IDOR / Object ID References**: Can an attacker pass an arbitrary UUID belonging to another organization to perform operations?
- [ ] **Bulk / Batch Operations**: Do batch update/delete APIs verify that *every* item in the target list belongs to the authenticated tenant?

## 3. Discriminating Test Vector
```python
def test_cross_tenant_access_blocked():
    tenant_a_doc = create_document(tenant_id="tenant-A")
    client_b = authenticated_client(tenant_id="tenant-B")
    
    response = client_b.get(f"/api/v1/documents/{tenant_a_doc.id}")
    assert response.status_code in [403, 404], f"Cross-tenant leak detected: {response.status_code}"
```
