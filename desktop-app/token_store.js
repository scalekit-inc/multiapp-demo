import keytar from "keytar";

const SERVICE = "example_desktop_app";
const ACCOUNT = "default";

export async function saveTokens(tokens) {
  await keytar.setPassword(SERVICE, ACCOUNT, JSON.stringify(tokens));
}

export async function loadTokens() {
  const raw = await keytar.getPassword(SERVICE, ACCOUNT);
  return raw ? JSON.parse(raw) : null;
}

export async function clearTokens() {
  await keytar.deletePassword(SERVICE, ACCOUNT);
}
