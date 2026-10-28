/**
 * @name Request-controlled value reaches an unscoped or attacker-controlled ORM lookup
 * @description A value from the request is used in an ORM lookup through the model's
 *              manager or query chain (Model.objects, _default_manager, get_object_or_404) where either:
 *              1. No positive tenant/org/owner predicate is provided in the call or receiver chain, OR
 *              2. The tenant scoping keyword argument itself receives untrusted remote input.
 *              Caveat: Flagged sites represent candidate lookups requiring architecture and runtime
 *              verification; database-level PostgreSQL RLS or schema-per-tenant require separate verification.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id code-logic-auditor/python/unscoped-tenant-lookup
 * @tags purpose/candidate-discovery security external/cwe/cwe-639 classification/TENANT-LEAK
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

/** Keyword names that indicate candidate tenant or organizational scoping. */
bindingset[k]
predicate isScopingKeyword(string k) {
  k.regexpMatch("(?i).*(tenant|org|organi[sz]ation|company|account|owner|workspace).*")
}

/** Matches Model.objects, Model._default_manager, etc. */
bindingset[attr]
predicate isManagerAttribute(string attr) {
  attr.regexpMatch("(?i)(objects|_default_manager|all_objects)")
}

/** Recursively matches a manager attribute or a chained queryset method call. */
predicate isQuerysetOrManager(DataFlow::Node n) {
  isManagerAttribute(n.(DataFlow::AttrRead).getAttributeName())
  or
  exists(DataFlow::MethodCallNode chain |
    chain = n and
    chain.getMethodName() in ["select_related", "prefetch_related", "filter", "exclude", "all", "order_by", "only", "defer", "using"] and
    isQuerysetOrManager(chain.getObject())
  )
}

/** Scope shape on the receiver chain; this is not a provenance/trust proof. */
predicate hasPositiveScope(DataFlow::Node n) {
  exists(DataFlow::MethodCallNode c, string k |
    c = n and c.getMethodName() = "filter" and
    isScopingKeyword(k) and exists(c.getArgByName(k))
  )
  or
  exists(DataFlow::MethodCallNode c |
    c = n and
    c.getMethodName() in ["select_related", "prefetch_related", "filter", "exclude", "all", "order_by", "only", "defer", "using"] and
    hasPositiveScope(c.getObject())
  )
}

/** A call missing both immediate and inherited positive scoping predicates. */
predicate lookupMissingScopeKeyword(DataFlow::MethodCallNode call) {
  call.getMethodName() in ["get", "filter", "exclude", "get_or_create", "update_or_create", "update", "delete", "aget", "aget_or_create", "aupdate_or_create", "aupdate", "adelete", "in_bulk"] and
  isQuerysetOrManager(call.getObject()) and
  not exists(string k | exists(call.getArgByName(k)) and isScopingKeyword(k)) and
  not hasPositiveScope(call.getObject())
}

/** Relations named user/principal are not name-based trust sanitizers. */
predicate getObjectOr404MissingScope(DataFlow::CallCfgNode call) {
  call = API::moduleImport("django.shortcuts").getMember("get_object_or_404").getACall() and
  not exists(string k | exists(call.getArgByName(k)) and isScopingKeyword(k)) and
  not hasPositiveScope(call.getArg(0))
}

/** A call like `Model.objects.get(...)` where a scoping keyword is present. */
predicate lookupWithScopeKeyword(DataFlow::MethodCallNode call, string k) {
  call.getMethodName() in ["get", "filter", "exclude", "get_or_create", "update_or_create", "update", "delete", "aget", "aget_or_create", "aupdate_or_create", "aupdate", "adelete", "in_bulk"] and
  isQuerysetOrManager(call.getObject()) and
  isScopingKeyword(k) and
  exists(call.getArgByName(k))
}

module UnscopedLookupConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    // Case 1: Call lacks any scoping keyword; lookup arguments are sinks
    exists(DataFlow::MethodCallNode c | lookupMissingScopeKeyword(c) |
      n = c.getArgByName(_) or n = c.getArg(_) or n = c.getKwargs()
    )
    or
    // Case 2: get_object_or_404 call lacking scoping keyword
    exists(DataFlow::CallCfgNode c | getObjectOr404MissingScope(c) |
      n = c.getArgByName(_) or n = c.getArg(_) or n = c.getKwargs()
    )
    or
    // Case 3: Scoping keyword is present, but its argument value is tainted by untrusted input
    exists(DataFlow::CallCfgNode c, string k |
      (
        lookupWithScopeKeyword(c.(DataFlow::MethodCallNode), k)
        or
        (c = API::moduleImport("django.shortcuts").getMember("get_object_or_404").getACall() and
         isScopingKeyword(k) and exists(c.getArgByName(k)))
      ) |
      n = c.getArgByName(k)
    )
  }

  // No name-based user/session/auth barriers. Provenance is evaluated separately.

}

module UnscopedLookupFlow = TaintTracking::Global<UnscopedLookupConfig>;

import UnscopedLookupFlow::PathGraph

from UnscopedLookupFlow::PathNode source, UnscopedLookupFlow::PathNode sink
where UnscopedLookupFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Request-controlled $@ reaches an ORM lookup lacking verified principal tenant scoping.", source.getNode(),
  "value"
