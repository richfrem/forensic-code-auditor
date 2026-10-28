/**
 * @name Candidate: remote lifecycle mutation requires operation review
 * @description Inventory of direct, setter, bulk-body and raw SQL mutation candidates.
 *              A named canTransition/validateState function is not a verified sanitizer.
 *              Protected guards and storage policies must be evaluated manually.
 * @kind path-problem
 * @problem.severity warning
 * @precision low
 * @id code-logic-auditor/js/unguarded-state-transition
 * @tags security external/cwe/cwe-841 classification/FSM-BYPASS purpose/candidate-discovery
 */
import javascript

module StateTransitionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) {
    exists(DataFlow::PropWrite w |
      w.getPropertyName().regexpMatch("(?i)(status|state|stage|phase|lifecycle)") and n = w.getRhs()
    )
    or
    exists(DataFlow::MethodCallNode c |
      c.getMethodName().regexpMatch("(?i)(setStatus|setState|transitionTo)") and n = c.getArgument(0)
    )
    or
    exists(DataFlow::MethodCallNode c |
      c.getMethodName() = "assign" and c.getReceiver().asExpr().toString() = "Object" and n = c.getArgument(1)
    )
    or
    exists(DataFlow::PropWrite w |
      w.getPropertyName() = "data" and n = w.getRhs()
    )
    or
    exists(DataFlow::MethodCallNode c |
      c.getMethodName() in ["query", "execute", "$executeRaw", "$queryRaw"] and n = c.getArgument(1)
    )
  }
}
module StateTransitionFlow = TaintTracking::Global<StateTransitionConfig>;
import StateTransitionFlow::PathGraph
from StateTransitionFlow::PathNode source, StateTransitionFlow::PathNode sink
where StateTransitionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Candidate: $@ reaches a state mutation; authorization and legal transition are NOT VERIFIED.", source.getNode(), "remote input"
