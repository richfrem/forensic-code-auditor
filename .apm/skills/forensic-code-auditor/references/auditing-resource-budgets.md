# Resource budgets and cancellation runbook

## Contents

- [Scope and invariant](#scope-and-invariant)
- [Reconstruct cost and recovery](#reconstruct-cost-and-recovery)
- [Discriminating proof and coverage](#discriminating-proof-and-coverage)

## Scope and invariant

Use when discovered input can consume shared CPU, memory, disk, handles, connections, workers,
queue capacity or operator-funded calls. Apply [the contract](../instructions.md). Distinguish a
sourced shared availability, fairness or spend boundary from ordinary performance improvement.
A missing rate limit or expensive authorized operation alone is not a vulnerability.

## Reconstruct cost and recovery

1. Map accepted input → expansion/evaluation → downstream fan-out → retained resource → recovery.
   Record requester effort, pre-authentication work, process/tenant scope, per-item and aggregate
   bounds, enforcement owner, deadlines and cleanup. Include upstream/framework controls and unknown
   deployed limits. A transfer-size cap may not bound decompressed or recursively expanded data.
2. Inspect nesting, regexes, graph traversal, query cardinality, joins, pagination and unique cache/
   metric/session keys. Establish accepted input domains and growth; do not infer unbounded work
   merely from a loop. Compare per-object limits with task-wide, tenant-wide and process-wide limits.
3. Trace quota identity and atomic accounting across concurrent calls, aliases, retries, reconnects,
   account changes and delegated jobs. A caller-controlled task/key/tenant must not select another
   principal's budget or reset the sourced cumulative limit.
4. Follow timeout, disconnect, failed authorization and cancellation through children, queries,
   model/API calls and pending work. Determine who releases locks, reservations, handles and slots.
   Returning an error does not establish that downstream work stopped or costs were bounded.
5. Inspect poison records, retry ceilings, dead-letter/quarantine policy, startup scans, restore and
   repair loops. Identify whether one accepted input blocks a shared partition or repeatedly recreates
   work. For crashes/deadlocks, establish worker/supervisor scope and actual recovery before impact.
6. Compare normal and degraded scheduling, pool fairness and emergency capacity. Source the intended
   allocation; broad capacity, autoscaling or a circuit breaker is a defense only on the actual path.

## Discriminating proof and coverage

Never stress live or shared systems. Under explicit local reproduction authorization, use synthetic
inputs, a few small growth points, fake clocks, instrumented counters, mocked paid calls and forced
cancellation. Independently enforce CPU/memory/process/disk/time bounds before target execution.
Observe work and retention after cleanup should occur; stop at the minimum discriminatory result.
The recorder is not a sandbox, and a fixture's supervisor does not prove production recovery.

Attach the input/resource/bound table, complexity argument, recovery trace and unresolved upstream
controls to the nine-item dossier. Use RESOURCE-LEAK for established resource consumption/retention
boundary failures, or the actual primary cause when another existing category fits. Do not multiply
findings for every exhausted pool in one chain. Unknown caps, topology or spend policy cap assurance;
separate static proof from executed model observations. No load-test or detection gain is implied.
