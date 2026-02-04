
const KEY = "spa_tokens";

export function saveTokens(tokens) {
  localStorage.setItem(KEY, JSON.stringify(tokens));
}

export function loadTokens() {
  const raw = localStorage.getItem(KEY);
  try {
    const t = JSON.parse(raw);
    return t;
  } catch {
    // handle error here
    return null;
  }
}

export function clearTokens() {
  localStorage.removeItem(KEY);
}
