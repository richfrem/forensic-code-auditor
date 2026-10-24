/**
 * @name Request-controlled value reaches an unscoped or attacker-controlled ORM lookup
 * @description A value from the request is used in an ORM lookup through the model's
 *              root manager (Model.objects) where either:
 *              1. No tenant/org/owner keyword predicate is provided in the call, OR
 *              2. The tenant scoping keyword argument itself receives untrusted remote input.
 *              Caveat: Syntactic queries cannot verify database-level PostgreSQL Row-Level
 *              Security (RLS) policies or schema-per-tenant isolation; flagged sites represent
 *              candidate lookups requiring architecture and runtime verification.
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

/** Keyword names that indicate candidate tenant or organizational scoping. */
bindingset[k]
predicate isScopingKeyword(string k) {
  k.regexpMatch("(?i).*(tenant|org|organi[sz]ation|company|account|owner|workspace).*")
}

/** A call like `Model.objects.get(...)` / `.filter(...)` with no scoping keyword. */
predicate lookupMissingScopeKeyword(DataFlow::MethodCallNode call) {
  call.getMethodName() in ["get", "filter", "exclude", "get_or_create", "update_or_create"] and
  call.getObject().(DataFlow::AttrRead).getAttributeName() = "objects" and
  not exists(string k | exists(call.getArgByName(k)) and isScopingKeyword(k))
}

/** A call like `Model.objects.get(...)` where a scoping keyword is present. */
predicate lookupWithScopeKeyword(DataFlow::MethodCallNode call, string k) {
  call.getMethodName() in ["get", "filter", "exclude", "get_or_create", "update_or_create"] and
  call.getObject().(DataFlow::AttrRead).getAttributeName() = "objects" and
  isScopingKeyword(k) and
  exists(call.getArgByName(k))
}

module UnscopedLookupConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    // Case 1: Call lacks any scoping keyword; lookup arguments are sinks
    exists(DataFlow::MethodCallNode c | lookupMissingScopeKeyword(c) |
      n = c.getArgByName(_) or n = c.getArg(_)
    )
    or
    // Case 2: Scoping keyword is present, but its argument value is tainted by untrusted input
    exists(DataFlow::MethodCallNode c, string k | lookupWithScopeKeyword(c, k) |
      n = c.getArgByName(k)
    )
  }
}

module UnscopedLookupFlow = TaintTracking::Global<UnscopedLookupConfig>;

import UnscopedLookupFlow::PathGraph

from UnscopedLookupFlow::PathNode source, UnscopedLookupFlow::PathNode sink
where UnscopedLookupFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Request-controlled $@ reaches an ORM lookup lacking verified principal tenant scoping.", source.getNode(),
  "value"
