import crypto from "crypto";

export function base64Url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function randomString(bytes = 32) {
  return base64Url(crypto.randomBytes(bytes));
}

export function sha256(input) {
  return crypto.createHash("sha256").update(input).digest();
}

export function makePkce() {
  const code_verifier = randomString(32);
  const code_challenge = base64Url(sha256(code_verifier));
  return { code_verifier, code_challenge, method: "S256" };
}

export function buildAuthorizeUrl({
  issuerBaseUrl,
  clientId,
  redirectUri,
  scope,
  state,
  codeChallenge,
  codeChallengeMethod = "S256",
}) {
  const url = new URL("/oauth/authorize", issuerBaseUrl);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", scope);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", codeChallengeMethod);
  return url.toString();
}

export function buildOidcLogoutUrl({ issuerBaseUrl, idTokenHint, postLogoutRedirectUri }) {
  const url = new URL("/oidc/logout", issuerBaseUrl);
  url.searchParams.set("id_token_hint", idTokenHint);
  url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);
  return url.toString();
}

export async function exchangeCodeForTokens({
  issuerBaseUrl,
  clientId,
  code,
  redirectUri,
  codeVerifier,
}) {
  const tokenUrl = new URL("/oauth/token", issuerBaseUrl);

  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("client_id", clientId);
  body.set("code", code);
  body.set("redirect_uri", redirectUri);
  body.set("code_verifier", codeVerifier);

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
  return json;
}

export async function refreshTokens({ issuerBaseUrl, clientId, refreshToken }) {
  const tokenUrl = new URL("/oauth/token", issuerBaseUrl);

  const body = new URLSearchParams();
  body.set("grant_type", "refresh_token");
  body.set("client_id", clientId);
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

export function decodeJwtPayload(jwt) {
  if (!jwt || typeof jwt !== "string") return null;
  const parts = jwt.split(".");
  if (parts.length < 2) return null;

  const base64Url = parts[1];
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);

  try {
    return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
  } catch {
    return null;
  }
}

export function computeExpiresAt({ accessToken, expiresIn }) {
  const now = Date.now();
  if (Number.isFinite(expiresIn)) return now + Number(expiresIn) * 1000;
  const p = decodeJwtPayload(accessToken);
  if (p?.exp) return p.exp * 1000;
  return now;
}
