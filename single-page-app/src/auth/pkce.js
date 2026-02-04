export function base64UrlEncode(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function sha256(input) {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

export function randomString(byteLen = 32) {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function makePkce() {
  const code_verifier = randomString(32);
  const challengeBytes = await sha256(code_verifier);
  const code_challenge = base64UrlEncode(challengeBytes);
  return { code_verifier, code_challenge };
}
