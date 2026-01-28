import { computeExpiresAt, decodeJwtPayload } from "./jwt";
import { makePkce, randomString } from "./pkce";
import { clearTokens, loadTokens, saveTokens } from "./storage";

const ISSUER_BASE_URL = import.meta.env.VITE_ISSUER_BASE_URL;
const CLIENT_ID = import.meta.env.VITE_CLIENT_ID;
const REDIRECT_URI = import.meta.env.VITE_REDIRECT_URI;
const POST_LOGOUT_REDIRECT_URI = import.meta.env.VITE_POST_LOGOUT_REDIRECT_URI;
const SCOPES = import.meta.env.VITE_SCOPES;

const EPHEMERAL_KEY = "spa_ephemeral";

function saveEphemeral(obj) {
  sessionStorage.setItem(EPHEMERAL_KEY, JSON.stringify(obj));
}

function loadEphemeral() {
  const raw = sessionStorage.getItem(EPHEMERAL_KEY);
  return raw ? JSON.parse(raw) : null;
}

function clearEphemeral() {
  sessionStorage.removeItem(EPHEMERAL_KEY);
}

export async function startLogin() {
  const { code_verifier, code_challenge } = await makePkce();
  const state = randomString(16);
  saveEphemeral({ code_verifier, state });

  const url = new URL("/oauth/authorize", ISSUER_BASE_URL);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", code_challenge);
  url.searchParams.set("code_challenge_method", "S256");

  window.location.assign(url.toString());
}

export async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const state = params.get("state");

  const eph = loadEphemeral();
  if (!code || !eph || eph.state !== state) throw new Error("Invalid callback");

  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("client_id", CLIENT_ID);
  body.set("code", code);
  body.set("redirect_uri", REDIRECT_URI);
  body.set("code_verifier", eph.code_verifier);

  const res = await fetch(`${ISSUER_BASE_URL}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const json = await res.json();
  if (!res.ok) throw new Error(JSON.stringify(json));

  const tokens = {
    access_token: json.access_token,
    refresh_token: json.refresh_token,
    id_token: json.id_token,
    expires_at: computeExpiresAt({ accessToken: json.access_token, expiresIn: json.expires_in }),
    access_payload: decodeJwtPayload(json.access_token)
  };

  saveTokens(tokens);
  clearEphemeral();
  return tokens;
}

export async function refreshIfNeeded({ earlyMs = 60000, force = false } = {}) {
  if (window.location.pathname === "/callback") {
    throw new Error("Refresh disabled during callback");
  }
  const t = loadTokens();
  if (!t) {
    return null;
  }

  if (!force && Date.now() < (t.expires_at - earlyMs)) return t;
  if (!t.refresh_token) {
    clearTokens();
    throw new Error("No refresh token");
  }

  const body = new URLSearchParams();
  body.set("grant_type", "refresh_token");
  body.set("client_id", CLIENT_ID);
  body.set("refresh_token", t.refresh_token);

  const res = await fetch(`${ISSUER_BASE_URL}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const json = await res.json();
  if (!res.ok) {
    clearTokens();
    clearEphemeral();
    throw new Error(JSON.stringify(json));
  }

  const updated = {
    ...t,
    access_token: json.access_token,
    refresh_token: json.refresh_token || t.refresh_token,
    id_token: json.id_token || t.id_token,
    expires_at: computeExpiresAt({ accessToken: json.access_token, expiresIn: json.expires_in }),
    access_payload: decodeJwtPayload(json.access_token)
  };

  saveTokens(updated);
  return updated;
}

export function logout() {
  const t = loadTokens();
  clearTokens();

  if (t?.id_token) {
    const url = new URL("/oidc/logout", ISSUER_BASE_URL);
    url.searchParams.set("id_token_hint", t.id_token);
    url.searchParams.set("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI);
    window.location.assign(url.toString());
  } else {
    window.location.assign("/logged-out");
  }
}

export function getTokens() {
  return loadTokens();
}
