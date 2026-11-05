# Inspection Prompt: Agentic Tool Boundary & MCP Execution Audit

## Contents

- [Dispatch and invocation](#1-tool-dispatch--invocation-lifecycle)
- [Invariant checklist](#2-invariant-checklist)
- [Discriminating test](#3-discriminating-test-vector)
- [Delegation and approval](#4-delegation-and-approval-binding)
- [Intent and representation](#5-intent-representation-and-connection-binding)

Execute this inspection to evaluate Model Context Protocol (MCP) server endpoints, autonomous agent tool dispatchers, tool-call authorization boundaries, and secondary prompt injection propagation.

## 1. Tool Dispatch & Invocation Lifecycle
- Trace how agent tool calls enter the runtime (e.g. JSON-RPC over `stdio`, `sse`, or HTTP POST).
- Verify whether the executing identity is authenticated per tool call or if the tool relies on ambient daemon/process permissions.
- Check whether destructive tool parameters (file paths, SQL filters, entity/ticket IDs, shell commands) are strictly validated against an immutable allowlist or if raw LLM generation is passed directly to system APIs.
- Trace downstream propagation: when Tool A returns data (e.g., ticket comments, git commit logs), is it returned to the agent context as untrusted data or does it bypass policy boundaries in Tool B?

## 2. Invariant Checklist
- [ ] **Caller Authorization Bound**: Does every MCP tool handler independently enforce caller identity and RBAC/ABAC permissions before executing side-effects, rather than assuming upstream agent authorization?
- [ ] **Ambient Identity Rejection**: Does the tool runner execute actions with the caller's delegated permissions, rather than running as a high-privileged service account with unrestricted system access?
- [ ] **Multi-Step Completion**: For sequences such as `create_branch` -> `commit_code` -> `open_pr`, does partial failure follow independently sourced completion/compensation policy? Retained partial state is not automatically a violation.
- [ ] **Tool Result Trust Boundary**: Do returned strings remain untrusted data through downstream processing, with authorization and action binding at the final sink? Sanitization alone does not grant authority or establish containment.
- [ ] **Human-in-the-Loop (HITL) Gate Integrity**: If a tool requires explicit human approval (destructive file write, production deploy, external network egress), can the agent bypass the gate via parameter aliasing or alternative tool routing?

## 3. Discriminating Test Vector
```python
def test_unauthorized_mcp_tool_execution_blocked():
    # Caller token belongs to unprivileged Viewer role
    viewer_client = get_mcp_client(role="viewer")
    
    before = read_committed_schema_version()
    queued_before = mock_queue.snapshot()
    external_before = mock_effects.snapshot()

    # Attempt destructive tool call
    result = viewer_client.call_tool(
        name="execute_database_migration",
        arguments={"schema_version": "v2.0", "force": True}
    )
    
    assert result.is_error, "Invariant breached: Unprivileged caller executed destructive tool"
    assert "PERMISSION_DENIED" in result.error_code
    assert read_committed_schema_version() == before
    assert mock_queue.snapshot() == queued_before
    assert mock_effects.snapshot() == external_before
```


## 4. Delegation and approval binding
For metadata carriers, hidden helper execution, dormant triggers, poisoned tool descriptions,
memory persistence and audit suppression, also follow [Agent runtime threats](../agent-runtime-threats.md).
Distinguish direct code execution from model-mediated tool selection and verify both authority paths.

Trace user → agent → delegation → tool → backend operation with connection identity and asynchronous
queue effects. A service account is allowed only under explicit scoped delegation; sanitization alone
cannot grant authority. Bind approval to exact action, resource, state/version, principal, scope,
expiry and single-use nonce. Test resource substitution, expired/replayed approval, indirect injected
instructions and alternate routing. Verify persisted state and queued/external mock effects, not merely
an error string. The example records committed state and mock effects; add action/resource/state/nonce substitution cases for the actual approval store. Do not assume rollback compensates
remote effects; inspect per-step compensation and report partial completion.

## 5. Intent, representation and connection binding
Separate resource authorization from action binding. A principal may be permitted to perform an
operation while hostile retrieved content causes an action that principal never requested. Compare
the intentional request or normalized approved action with the final action/resource/arguments used
by the handler. A generic confirmation or valid user credential does not establish that binding.

Follow defaults, coercion, aliases, duplicate fields and validation/dispatch conversions. Record the
validated object and consumed object; demonstrate a meaningful difference before reporting a schema
disagreement. For MCP, bind server/tool/resource namespaces and outstanding request IDs to the actual
authenticated connection across reconnects. Claimed server names or tool descriptions are not identity.

Pair authorized-but-unrequested action with intentionally requested action, substituted final arguments
and a mismatched connection/reply. Static tracing may prove a deterministic binding failure; a mock
model choice does not establish live model compliance. Preserve execution authorization and proof limits.
