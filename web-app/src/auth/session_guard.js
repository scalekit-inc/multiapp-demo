
const EARLY_REFRESH_MS = 60_000; // refresh 60 seconds before expiry

export function requireLogin(req, res, next) {
  if (!req.session?.tokens?.access_token) {
    return res.redirect("/login");
  }
  return next();
}
