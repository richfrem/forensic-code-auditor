/**
 * @name Remote input written to a lifecycle state field without a transition guard
 * @description A request value is written to a status/state/stage property (directly or in an
 *              ORM update payload) without first passing through a transition validator.
 *              A client can jump the entity to any state, e.g. PENDING -> FULFILLED.
 *              
 *              Modeling Assumption:
 *              This query models transition sanitization heuristically on the true-branch of
 *              recognized validator predicates.
 *              Caveats & Limitations:
 *              1. Entity Disconnect: Does not verify that the entity inspected in the guard is
 *                 the identical instance being written (e.g. wrong-object bypass).
 *              2. Concurrency: Does not verify transactional or lock boundaries between check
 *                 and persistence (TOCTOU race window).
 *              3. Completeness: Taint suppression alone does not constitute proof of verified
 *                 state-machine safety.
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

  /** The target state value (typically argument 1 or 0) is guarded on the true-branch. */
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
  "Lifecycle state is set from $@ without a verified transition guard.", source.getNode(), "remote input"
