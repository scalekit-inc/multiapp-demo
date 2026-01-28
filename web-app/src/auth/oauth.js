import crypto from "crypto";

/**
 * Build authorize URL with state for CSRF protection.
 */
export function buildAuthorizeUrl({ issuerBaseUrl, clientId, redirectUri, scope, state }) {
  const url = new URL("/oauth/authorize", issuerBaseUrl);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", scope);
  url.searchParams.set("state", state);
  return url.toString();
}

export function generateState() {
  return crypto.randomBytes(16).toString("hex");
}

/**
 * OIDC logout URL builder.
 * `id_token_hint` should be the `id_token` returned by /oauth/token.
 */
export function buildOidcLogoutUrl({ issuerBaseUrl, idTokenHint, postLogoutRedirectUri }) {
  const url = new URL("/oidc/logout", issuerBaseUrl);
  url.searchParams.set("id_token_hint", idTokenHint);
  url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);
  return url.toString();
}

/**
 * Token exchange (authorization_code)
 */
export async function exchangeCodeForTokens({
  issuerBaseUrl,
  clientId,
  clientSecret,
  code,
  redirectUri,
}) {
  const tokenUrl = new URL("/oauth/token", issuerBaseUrl);

  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("client_id", clientId);
  body.set("client_secret", clientSecret);
  body.set("code", code);
  body.set("redirect_uri", redirectUri);

  const res = await fetch(tokenUrl.toString(), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`Token exchange failed: ${res.status}`);
    err.details = json;
    throw err;
  }
  return json; // { access_token, refresh_token, id_token, expires_in, token_type, ... }
}

/**
 * Refresh token
 */
export async function refreshTokens({
  issuerBaseUrl,
  clientId,
  clientSecret,
  refreshToken,
}) {
  const tokenUrl = new URL("/oauth/token", issuerBaseUrl);

  const body = new URLSearchParams();
  body.set("grant_type", "refresh_token");
  body.set("client_id", clientId);
  body.set("client_secret", clientSecret);
  body.set("refresh_token", refreshToken);

  const res = await fetch(tokenUrl.toString(), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`Token refresh failed: ${res.status}`);
    err.details = json;
    throw err;
  }
  return json;
}

/**
 * Decode JWT payload (no signature verification; only for reading exp, sub, etc).
 * Safe to use for "when does it expire" and showing UI/debugging, not for trusting permissions.
 */
export function decodeJwtPayload(jwt) {
  if (!jwt || typeof jwt !== "string") return null;
  const parts = jwt.split(".");
  if (parts.length < 2) return null;

  const base64Url = parts[1];
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);

  try {
    const json = Buffer.from(padded, "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Computes expires_at (ms) from either expires_in (seconds) or JWT exp.
 */
export function computeExpiresAt({ accessToken, expiresIn }) {
  const now = Date.now();

  if (Number.isFinite(expiresIn)) {
    return now + Number(expiresIn) * 1000;
  }

  const payload = decodeJwtPayload(accessToken);
  if (payload?.exp) {
    return payload.exp * 1000;
  }

  // Worst case: treat as already expired so middleware refreshes immediately (or fails fast)
  return now;
}
