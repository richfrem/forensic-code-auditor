function checkUserAccess(req, resourceId) {
  try {
    return queryDatabaseAcl(req.user, resourceId);
  } catch (err) {
    // ruleid: fail-open-authorization-handler
    return true;
  }
}

const isAllowedArrow = (user, op) => {
  try {
    return evaluatePolicy(user, op);
  } catch (e) {
    // ruleid: fail-open-authorization-handler
    return { allowed: true };
  }
};

class AccessController {
  hasPrivilege(user, role) {
    try {
      return lookupLdap(user, role);
    } catch (err) {
      // ruleid: fail-open-authorization-handler
      return "ALLOW";
    }
  }
}

function checkUserAccessSafe(req, resourceId) {
  try {
    return queryDatabaseAcl(req.user, resourceId);
  } catch (err) {
    // ok: fail-open-authorization-handler
    return false;
  }
}
