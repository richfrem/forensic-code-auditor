# Inspection Prompt: Oracle Forms & Legacy PL/SQL Authorization Audit

> [!IMPORTANT]
> **Governing Doctrine**: All inspections are governed by `instructions.md` (First-Principles Epistemology, Invariant Sourcing, and Four Evidence Levels). Reject appeals to tradition ("this Form has run safely in production for 15 years"). Verify whether authorization invariants reside strictly in client UI triggers or are enforced at the database storage engine.

Execute this inspection when auditing enterprise legacy Oracle Forms (FMB/XML), Oracle Reports, PL/SQL package libraries (PLL/PLD), and database triggers undergoing modern API exposure, re-platforming, microservice extraction, or invariant auditing.

## 1. Oracle Forms & PL/SQL Library Source Extraction
Binary `.fmb`, `.mmb`, and `.pll` files cannot be inspected directly by static analysis. Convert them to inspectable plain text:

Work only on authorized offline copies. Inventory FMB/MMB/PLL and object-library attachments,
record hashes, exact Forms/Oracle versions and conversion-tool availability. Use a matching
Forms XML conversion tool for FMB/MMB and library text export for PLL where supported by that
version; verify tool help first. Do not embed usernames/passwords in command lines, reports or logs.
If tools are unavailable, request sanitized XML/PLD exports and mark binary/dynamic edges unknown.
Never connect conversion tooling to a live enterprise database.

## 2. Invariant Checklist: Client-Enforced vs Storage-Enforced Rules

### A. Client UI Validation Monopoly vs API Bypass
- [ ] **UI Item Disabling as Authorization**: Does the application rely on `SET_ITEM_PROPERTY('<item>', ENABLED, PROPERTY_FALSE)` or `SET_ITEM_PROPERTY('<item>', UPDATE_ALLOWED, PROPERTY_FALSE)` to prevent unauthorized updates, while the underlying table or procedure allows updates directly?
- [ ] **Client Validation Monopoly**: Do business and authorization invariants live solely inside Form client triggers (`WHEN-VALIDATE-ITEM`, `WHEN-VALIDATE-RECORD`, `PRE-INSERT`, `PRE-UPDATE`)?
  - *Vulnerability*: Any modern REST API wrapper, batch script, microservice, or direct SQL*Net caller bypasses client triggers completely, writing invalid state directly to tables.
- [ ] **Ambient `:GLOBAL.*` Trust**: Are security attributes (e.g. `:GLOBAL.USER_ROLE`, `:GLOBAL.IS_ADMIN`) initialized once at login and trusted across foreign form invocations (`CALL_FORM`, `OPEN_FORM`) without server-side signature or re-querying database privileges?
- [ ] **Menu Security (`USE_SECURITY`)**: Does menu security rely on Oracle Forms menu role properties (`USE_SECURITY = YES`) without backend row-level or package-level validation?

### B. Exception Swallows & Permissive Defaults
- [ ] **Error Suppression via `:SYSTEM.MESSAGE_LEVEL`**: Does code set `:SYSTEM.MESSAGE_LEVEL := '25'` or higher without immediately restoring it, silently discarding fatal database trigger and constraint errors?
- [ ] **Fail-Open `ON-ERROR` and `ON-MESSAGE` Triggers**: Does an `ON-ERROR` trigger catch database errors without executing `RAISE FORM_TRIGGER_FAILURE;`?
  - *Vulnerability*: Swallowing the error allows the form to advance to navigation or commit stages with invalid or partially committed records.
- [ ] **Fail-Open Function Exceptions**: In security checks (`can_access`, `chk_auth`, `is_authorized`), does `EXCEPTION WHEN OTHERS` or `WHEN NO_DATA_FOUND` return `TRUE`, `'Y'`, or set an allow variable?
- [ ] **VPD / Row-Level Security Predicate Disablement**: Do Virtual Private Database policy functions return `NULL` or empty strings upon `NO_DATA_FOUND` or normal paths, causing Oracle to omit the security WHERE clause and expose all rows?
- [ ] **Autonomous Transaction Mutating Table Workarounds**: Does a database trigger declare `PRAGMA AUTONOMOUS_TRANSACTION` to avoid `ORA-04091` (mutating table error)?

### C. Direct Database Privilege & Grants Inventory
- [ ] **Connection Account Privilege Escalation**: What direct operations can the Forms runtime database connection perform without the Forms client? Obtain from an authorized export:
```sql
-- Inventory direct table and procedure privileges for the runtime account
SELECT table_name, privilege FROM user_tab_privs;
SELECT role FROM user_role_privs;

-- CRITICAL: Check whether the connection holds EXEMPT ACCESS POLICY
SELECT * FROM session_privs WHERE privilege = 'EXEMPT ACCESS POLICY';
```
*(If `EXEMPT ACCESS POLICY` is granted, Oracle VPD / FGAC policies are completely bypassed for all connections made by that user.)*

## 3. Hierarchy, policy and execution reconstruction

Load [authorization data integrity](../authorization-data-integrity.md) and
[cross-entrypoint authorization](../cross-entrypoint-authorization.md). Expand menu → submenu →
form → trigger → package → operation, including rarely used, hidden, disabled and legacy branches.
Compare independent policy with effective Level 1/2 rows and actual operation checks. Correct code
can enforce an incorrect row exactly as programmed: identify its key and effective privilege.

Inspect AUTHID DEFINER/CURRENT_USER, owner/direct/role/PUBLIC grants, nested roles, synonyms,
qualified and dynamic SQL, VPD/RLS installation and bypass accounts. Track :GLOBAL, package/session
state, trusted context setters and connection-pool checkout/reset. Verify exact deployed version
semantics using matching manuals or disposable runtime; do not infer them from fixture SQLite.
Privilege queries above describe evidence to obtain from authorized configuration exports, not
permission to connect to a real database. A missing grant export is an unresolved boundary.

## 4. Discriminating tests and effects

Use a provisioned disposable local schema and synthetic accounts only. Derive allowed/denied
principals from independent policy; test Forms route and direct procedure/API route under each
connection identity. Assert persisted claim status, audit/outbox rows and external mock ledgers from
a fresh connection after commit. Rejection must leave all effects absent. Catch only the expected
authorization error; an arbitrary SQL/schema/connection failure is NOT proof of a defense.
Inspect autonomous transactions, explicit commits and external effects separately: rollback alone
cannot undo them and never makes a shared/live database safe for these tests.

Executable local model: [runtime.py](../../tests/fixtures/authorization/runtime.py).
Limitation: no FMB extraction, Oracle runtime, definer/invoker rights or VPD behavior is dynamically
verified by that model. Report Oracle execution `NOT_VERIFIED` until a faithful isolated schema runs.
