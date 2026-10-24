# Inspection Prompt: Oracle Forms & Legacy PL/SQL Authorization Audit

> [!IMPORTANT]
> **Governing Doctrine**: All inspections are governed by `instructions.md` (First-Principles Epistemology, Invariant Sourcing, and Four Evidence Levels). Reject appeals to tradition ("this Form has run safely in production for 15 years"). Verify whether authorization invariants reside strictly in client UI triggers or are enforced at the database storage engine.

Execute this inspection when auditing enterprise legacy Oracle Forms (FMB/XML), Oracle Reports, PL/SQL package procedures, and database triggers undergoing modern API exposure, re-platforming, microservice extraction, or invariant auditing.

## 1. Oracle Forms Source Extraction & Pipeline
Binary `.fmb` / `.mmb` files cannot be inspected directly by static analysis. Convert binary forms to XML using the Oracle Forms Translation Tool:
```bash
# Convert binary Oracle Form to XML for static AST/XPath inspection
frmf2xml.sh OVERWRITE=YES <form_name>.fmb
# Result: <form_name>_fmb.xml
```

## 2. Invariant Checklist: Client-Enforced vs Storage-Enforced Rules
- [ ] **Client UI Validation Monopoly**: Do business and authorization invariants live solely inside Form client triggers (`WHEN-VALIDATE-ITEM`, `WHEN-VALIDATE-RECORD`, `PRE-INSERT`, `PRE-UPDATE`)?
  - *Vulnerability*: Any modern REST API wrapper, batch script, or direct SQL*Net caller bypasses client triggers completely, writing invalid state directly to tables.
- [ ] **Error Suppression via `:SYSTEM.MESSAGE_LEVEL`**: Does code set `:SYSTEM.MESSAGE_LEVEL := '25'` or higher without restoring it, silently discarding fatal database trigger and constraint errors?
- [ ] **Fail-Open `ON-ERROR` and `ON-MESSAGE` Triggers**: Does an `ON-ERROR` trigger catch database errors without executing `RAISE FORM_TRIGGER_FAILURE;`?
  - *Vulnerability*: Swallowing the error allows the form to advance to navigation or commit stages with invalid or partially committed records.
- [ ] **Fail-Open Function Exceptions**: In security checks (`can_access`, `chk_auth`), does `EXCEPTION WHEN OTHERS` return `TRUE`, `'Y'`, or `NULL`?
- [ ] **VPD / Row-Level Security Predicate Disablement**: Do Virtual Private Database policy functions return `NULL` or empty strings upon `NO_DATA_FOUND` or errors, causing Oracle to omit the security WHERE clause and expose all rows?
- [ ] **Autonomous Transaction Mutating Table Workarounds**: Does a database trigger declare `PRAGMA AUTONOMOUS_TRANSACTION` to avoid `ORA-04091` (mutating table error)?
  - *Vulnerability*: The trigger reads uncommitted data from an isolated session, and its mutations commit even if the triggering statement subsequently rolls back.

## 3. Discriminating Test Vector
```sql
-- Demonstrate that bypassing Oracle Form client triggers permits illegal state insertion
-- Directly invoke the backend stored procedure or table insert with invalid state:
BEGIN
  -- Sourced Invariant: Document total must match sum of line items; status cannot jump to APPROVED
  INSERT INTO permits (permit_id, status, amount, approved_by)
  VALUES (9999, 'APPROVED', -5000, 'UNAUTHORIZED_USER');
  
  -- If this succeeds without raising an ORA- constraint error,
  -- the invariant is enforced ONLY in the Oracle Form UI, breaching storage integrity.
  COMMIT;
END;
/
```
