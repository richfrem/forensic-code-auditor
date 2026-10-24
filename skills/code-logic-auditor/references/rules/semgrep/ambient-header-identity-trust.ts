function extractIdentityUnsafe(req) {
  // ruleid: ambient-header-identity-trust
  const user = req.headers['x-forwarded-user'];
  // ruleid: ambient-header-identity-trust
  const siteminder = req.headers['sm_user'];
  return { user, siteminder };
}

function extractIdentitySafe(req) {
  // ok: ambient-header-identity-trust
  verifySignature(req);
  const user = req.headers['x-forwarded-user'];
  return user;
}
