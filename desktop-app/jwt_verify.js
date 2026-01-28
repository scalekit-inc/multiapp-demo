// jwt_verify.js
import { createRemoteJWKSet, jwtVerify } from "jose";

export function makeVerifier({ issuer, audience, jwksUri }) {
  const jwks = createRemoteJWKSet(new URL(jwksUri));

  return async function verifyJwtStrict(jwt) {
    const { payload } = await jwtVerify(jwt, jwks, {
      issuer,
      audience,
    });
    return payload;
  };
}
