/**
 * @name Remote input written to a lifecycle state field without a transition guard
 * @description A request value is written to a status/state/stage property (directly or in an
 *              ORM update payload) without first passing through a transition validator.
 *              A client can jump the entity to any state, e.g. PENDING -> FULFILLED.
 *              Rename the guard pattern below to match your codebase's validator.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id code-logic-auditor/js/unguarded-state-transition
 * @tags security external/cwe/cwe-841 classification/FSM-BYPASS
 */

import javascript

/** A call to a transition validator, e.g. `canTransition(from, to)`. Adjust the regex. */
class TransitionGuard extends DataFlow::CallNode {
  TransitionGuard() {
    this.getCalleeName().regexpMatch("(?i).*(isValidTransition|canTransition|validateTransition|assertTransition|validateState).*")
  }

  /** The guarded value is safe on the branch where the guard returned true. */
  predicate blocksExpr(boolean outcome, Expr e) {
    outcome = true and e = this.getAnArgument().asExpr()
  }
}

module StateTransitionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(DataFlow::PropWrite w |
      w.getPropertyName().regexpMatch("(?i)(status|state|stage|phase|lifecycle)") and
      n = w.getRhs()
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    n = DataFlow::MakeBarrierGuard<TransitionGuard>::getABarrierNode()
  }
}

module StateTransitionFlow = TaintTracking::Global<StateTransitionConfig>;

import StateTransitionFlow::PathGraph

from StateTransitionFlow::PathNode source, StateTransitionFlow::PathNode sink
where StateTransitionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Lifecycle state is set from $@ without a transition guard.", source.getNode(), "remote input"
