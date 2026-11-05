# Incremental audit revalidation runbook

## Contents

- [Scope and retained evidence](#scope-and-retained-evidence)
- [Reconstruct current work](#reconstruct-current-work)
- [Reconcile and report](#reconcile-and-report)

## Scope and retained evidence

Use when resuming an audit or comparing a prior report with a new source/policy/runtime snapshot.
Apply [the contract](../instructions.md). Prior findings, source paths and verdicts are claims to
recheck; their existence does not establish current behavior. Run mandatory discovery on the current
scope before routing. A diff helps prioritize work but does not discover unchanged alternate callers,
external policy changes or generated/runtime paths by itself.

## Reconstruct current work

1. Preserve prior reports, source/export digests, scope/exclusions, tool versions and unresolved items
   as read-only evidence. Record missing or incompatible prior artifacts. Never replace prior evidence
   files in place to make their hashes match current source.
2. Build a reconciliation artifact with prior finding/operation ID, current operation ID, invariant,
   source-defined sink, authority boundary, relevant source/policy/runtime revisions, prior/current
   disposition, evidence references and reason. Keep the same root-cause identity across wording or
   verdict changes; record explicit mappings for renamed/split/merged operations. Line numbers and
   titles alone are unstable identities. Do not invent fields in the canonical report schema.
3. Recheck the full dependency set: caller, guard, evaluator rows, policy, session identity, transaction,
   downstream defenses and effects. Unchanged sink bytes do not establish unchanged reachability or
   authority. Mark unavailable dependencies unresolved and reopen affected operation-dossier items.
4. Revalidate changed-source and changed-policy findings as current work. Carry a prior established
   claim only after its current path, invariant and proof applicability are reviewed and referenced.
   A prior reproduction remains a historical execution; it is not a new DYNAMIC_REPRODUCED result.
   Use current sufficient static proof or an authorized fresh reproduction for the current claim.
5. Reopen deferred, unsupported, excluded and unresolved operations when now in scope. A previous
   REFUTED claim suppresses only that exact hypothesis under unchanged relevant conditions; it never
   establishes that the operation has no other flaw. Keep prior reviewed operations visible too.
6. For each reopened item retain prior evidence, the changed premise, strongest current defense,
   discriminator and result. Do not overwrite an earlier attempt when later evidence contradicts it.

## Reconcile and report

Complete or explicitly leave unresolved all nine items for every selected current operation. Link the
reconciliation artifact through existing dossier evidence/coverage references. Add manually discovered
current operations to discovery before report validation; an ID mapping must not hide a new candidate.
Keep relevant prior artifacts under the ignored evidence root when the current report references them.

Report reviewed revisions, newly discovered paths, carried/revised/refuted/unresolved claims and
remaining exclusions. No prior clean conclusion transfers to a new snapshot. Validate the current
schema-v2 report and inspect the reconciliation manually: the validator checks declared artifacts
and candidate accounting, not whether a dependency set or cross-run identity mapping is complete.
