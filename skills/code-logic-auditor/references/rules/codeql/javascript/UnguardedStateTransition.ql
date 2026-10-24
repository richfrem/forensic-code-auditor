/**
 * @name Remote input written to a lifecycle state field without a transition guard
 * @description A request value is written to a status/state/stage property (directly or in an
 *              ORM update payload) without first passing through a transition validator, or where
 *              the transition validator inspected a different entity (wrong-object bypass).
 *              A client can jump the entity to an unauthorized state.
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

/**
 * Holds if `guard` validates variable `stateVar` specifically against `checkedEntity`
 * (e.g., `canTransition(orderA.status, next)`).
 */
predicate guardChecksEntity(TransitionGuard guard, VarAccess checkedEntity, Variable stateVar) {
  exists(VarAccess stateAccess |
    stateAccess = guard.getAnArgument().asExpr() and
    stateVar = stateAccess.getVariable()
  ) and
  exists(PropAccess pa |
    pa = guard.getAnArgument().asExpr() and
    checkedEntity = pa.getBase()
  )
}

/**
 * Holds if `w` writes a variable `stateVar` to `targetEntity.status`, where an enclosing `TransitionGuard`
 * validated `stateVar` against a DIFFERENT entity `checkedEntity`.
 */
predicate isWrongObjectBypass(DataFlow::PropWrite w) {
  exists(TransitionGuard g, VarAccess checkedEntity, VarAccess targetEntity, VarAccess writtenAccess, Variable stateVar |
    writtenAccess = w.getRhs().asExpr() and
    stateVar = writtenAccess.getVariable() and
    guardChecksEntity(g, checkedEntity, stateVar) and
    targetEntity = w.getBase().asExpr() and
    checkedEntity.getVariable() != targetEntity.getVariable()
  )
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
    n = DataFlow::MakeBarrierGuard<TransitionGuard>::getABarrierNode() and
    not exists(DataFlow::PropWrite w | isWrongObjectBypass(w) and n = w.getRhs())
  }
}

module StateTransitionFlow = TaintTracking::Global<StateTransitionConfig>;

import StateTransitionFlow::PathGraph

from StateTransitionFlow::PathNode source, StateTransitionFlow::PathNode sink
where StateTransitionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Lifecycle state is set from $@ without a valid entity transition guard.", source.getNode(), "remote input"
