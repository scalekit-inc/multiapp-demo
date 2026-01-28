import { createRemoteJWKSet, jwtVerify } from "jose";

const issuer = import.meta.env.VITE_ISSUER_BASE_URL;
const audience = import.meta.env.VITE_CLIENT_ID;

export function decodeJwtPayload(jwt) {
  if (!jwt) return null;
  const parts = jwt.split(".");
  if (parts.length < 2) return null;

  const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return JSON.parse(atob(padded));
}

export function computeExpiresAt({ accessToken, expiresIn }) {
  const now = Date.now();
  if (expiresIn) return now + expiresIn * 1000;
  const p = decodeJwtPayload(accessToken);
  return p?.exp ? p.exp * 1000 : now;
}

const jwks = createRemoteJWKSet(new URL(`${issuer}/keys`)); 
// If your issuer exposes jwks_uri via discovery, you can use that exact URL instead.

export async function verifyJwt(jwt) {
  const { payload, protectedHeader } = await jwtVerify(jwt, jwks, {
    issuer,
    audience
  });

  return { payload, protectedHeader };
}