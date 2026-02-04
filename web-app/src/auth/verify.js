import { createRemoteJWKSet, jwtVerify } from "jose";

export function makeJwtVerifier({ issuerBaseUrl, audience }) {
  // Best: use discovery jwks_uri. If you know your JWKS URL, put it here.
  const jwks = createRemoteJWKSet(new URL(`${issuerBaseUrl}/keys`));

  return async function verifyJwtStrict(token) {
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: issuerBaseUrl,
      audience
    });
    return { payload, protectedHeader };
  };
}
