function checkUserAccess(req, resourceId) {
  try {
    return queryDatabaseAcl(req.user, resourceId);
  } catch (err) {
    // ruleid: fail-open-authorization-handler
    return true;
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
