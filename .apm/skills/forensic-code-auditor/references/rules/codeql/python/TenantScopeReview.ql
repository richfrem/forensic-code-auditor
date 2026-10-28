/**
 * @name Tenant scope provenance and opaque mutation review
 * @description Candidate inventory, not a vulnerability verdict: keyword scope has unknown
 *              provenance, kwargs hide predicates, or raw/bulk operations need manual review.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id forensic-code-auditor/python/tenant-scope-review
 * @tags security external/cwe/cwe-639
 */
import python
import semmle.python.dataflow.new.DataFlow

from DataFlow::CallCfgNode call, string reason
where
  (
    exists(string k |
      k.regexpMatch("(?i).*(tenant|org|organi[sz]ation|company|account|owner|workspace).*") and
      exists(call.getArgByName(k))
    ) and reason = "Scope keyword present; trusted principal provenance is NOT VERIFIED."
  )
  or
  (exists(call.getKwargs()) and reason = "Expanded kwargs: effective scope needs inspection.")
  or
  (
    call.(DataFlow::MethodCallNode).getMethodName() in ["raw", "execute", "executemany", "update", "delete", "bulk_update", "bulk_create"] and
    reason = "Raw or bulk operation: inspect actual scope and identity provenance."
  )
select call, reason
