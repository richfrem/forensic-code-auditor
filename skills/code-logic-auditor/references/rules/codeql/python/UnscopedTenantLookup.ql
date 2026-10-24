/**
 * @name Request-controlled id reaches an unscoped ORM lookup
 * @description A value from the request is used to look up a row through the model's
 *              root manager (Model.objects) with no tenant/org/owner keyword in the same call.
 *              Any authenticated user can then address another tenant's row (IDOR).
 *              Scoped access (request.tenant.invoices.get(...), a tenant-filtered
 *              custom manager, Postgres RLS) is not flagged.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id code-logic-auditor/python/unscoped-tenant-lookup
 * @tags security external/cwe/cwe-639 classification/TENANT-LEAK
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

/** Keyword names that indicate the lookup is already scoped to a tenant or owner. */
bindingset[k]
predicate isScopingKeyword(string k) {
  k.regexpMatch("(?i).*(tenant|org|organi[sz]ation|company|account|owner|workspace).*")
}

/** A call like `Model.objects.get(...)` / `.filter(...)` with no scoping keyword. */
predicate unscopedLookup(DataFlow::MethodCallNode call) {
  call.getMethodName() in ["get", "filter", "exclude", "get_or_create", "update_or_create"] and
  call.getObject().(DataFlow::AttrRead).getAttributeName() = "objects" and
  not exists(string k | exists(call.getArgByName(k)) and isScopingKeyword(k))
}

module UnscopedLookupConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(DataFlow::MethodCallNode c | unscopedLookup(c) |
      n = c.getArgByName(_) or n = c.getArg(_)
    )
  }
}

module UnscopedLookupFlow = TaintTracking::Global<UnscopedLookupConfig>;

import UnscopedLookupFlow::PathGraph

from UnscopedLookupFlow::PathNode source, UnscopedLookupFlow::PathNode sink
where UnscopedLookupFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Request-controlled $@ reaches an ORM lookup with no tenant/owner predicate.", source.getNode(),
  "value"
