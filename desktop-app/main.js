// main.js
import crypto from "crypto";
import { app, BrowserWindow, ipcMain, shell } from "electron";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";

import { makeVerifier } from "./jwt_verify.js";
import {
  buildAuthorizeUrl,
  buildOidcLogoutUrl,
  computeExpiresAt,
  decodeJwtPayload,
  exchangeCodeForTokens,
  makePkce,
  refreshTokens,
} from "./oauth.js";

import { clearTokens, loadTokens, saveTokens } from "./token_store.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---- Config loaded from config.json ----
let CLIENT_ID = null;
let ISSUER_BASE_URL = null;

// ---- Loopback config ----
const LOOPBACK_HOST = "127.0.0.1";
const LOOPBACK_PORT = 53682; // fixed port
const REDIRECT_URI = `http://${LOOPBACK_HOST}:${LOOPBACK_PORT}/callback`;
const POST_LOGOUT_REDIRECT_URI = `http://${LOOPBACK_HOST}:${LOOPBACK_PORT}/logged-out`;
const SCOPES = "openid email profile offline_access";

let mainWindow;
let pendingLogin = null; // { state, code_verifier }
let loopbackServer = null;

// -------------------- Window + messaging --------------------

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 560,
    height: 520,
    webPreferences: {
      contextIsolation: false,
      nodeIntegration: true,
    },
  });

  mainWindow.loadFile(path.join(__dirname, "index.html"));
}

function sendStatus(payload) {
  mainWindow?.webContents?.send("status", payload);
}

// New: session change event (UI can update pill/button visibility)
function sendSessionChanged({ isLoggedIn, reason, tokenMeta } = {}) {
  mainWindow?.webContents?.send("session_changed", {
    isLoggedIn: Boolean(isLoggedIn),
    reason: reason || null,
    token_meta: tokenMeta || null,
    at: Date.now(),
  });
}

async function emitSessionFromStore(reason = null) {
  const t = await loadTokens();
  const isLoggedIn = Boolean(t?.access_token);
  sendSessionChanged({
    isLoggedIn,
    reason,
    tokenMeta: t ? { expires_at: t.expires_at, obtained_at: t.obtained_at } : null,
  });
}

// -------------------- Config --------------------

async function loadConfig() {
  const cfgPath = path.join(__dirname, "config.json");
  try {
    const raw = await import(`file://${cfgPath}`, { assert: { type: "json" } });
    CLIENT_ID = raw.default?.client_id || null;
    ISSUER_BASE_URL = raw.default?.issuer_base_url || null;
  } catch {
    try {
      const fs = await import("fs");
      const raw = fs.readFileSync(cfgPath, "utf8");
      const parsed = JSON.parse(raw);
      CLIENT_ID = parsed.client_id || null;
      ISSUER_BASE_URL = parsed.issuer_base_url || null;
    } catch (e) {
      CLIENT_ID = null;
      ISSUER_BASE_URL = null;
    }
  }
}

// -------------------- Tiny HTML pages for loopback browser tab --------------------

function htmlPage({ title, body }) {
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; background:#f6f8fb; margin:0; color:#0f172a; }
      .wrap { max-width: 720px; margin: 48px auto; padding: 0 20px; }
      .card { background: white; border: 1px solid #e2e8f0; border-radius: 14px; padding: 20px; box-shadow: 0 8px 22px rgba(15,23,42,0.06); }
      h1 { font-size: 20px; margin: 0 0 8px; }
      p { margin: 8px 0; color: #334155; line-height: 1.5; }
      code, pre { background: #0b1220; color: #e5e7eb; padding: 12px; border-radius: 12px; display:block; overflow:auto; }
      .muted { color:#64748b; font-size: 13px; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        ${body}
        <p class="muted">You may now close this tab and return to the desktop app.</p>
      </div>
    </div>
  </body>
</html>`;
}

// -------------------- Loopback server --------------------

function startLoopbackServer() {
  if (loopbackServer) return;

  loopbackServer = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://${LOOPBACK_HOST}:${LOOPBACK_PORT}`);

      if (url.pathname === "/callback") {
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const err = url.searchParams.get("error");
        const errDesc = url.searchParams.get("error_description") || "";

        if (err) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end(
            htmlPage({
              title: "OAuth error",
              body: `<h1>❌ Login failed</h1><p>${err}: ${errDesc}</p>`,
            })
          );
          sendStatus({ ok: false, message: `OAuth error: ${err}`, details: errDesc });
          await emitSessionFromStore("oauth_error");
          return;
        }

        if (!pendingLogin) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end(
            htmlPage({
              title: "No login in progress",
              body: `<h1>❌ No login in progress</h1><p>Return to the app and click “Login” again.</p>`,
            })
          );
          sendStatus({ ok: false, message: "No login in progress (missing PKCE state)." });
          await emitSessionFromStore("no_login_in_progress");
          return;
        }

        if (!code || !state || state !== pendingLogin.state) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end(
            htmlPage({
              title: "State mismatch",
              body: `<h1>❌ State mismatch</h1><p>Please retry login from the app.</p>`,
            })
          );
          sendStatus({ ok: false, message: "State mismatch or missing code." });
          await emitSessionFromStore("state_mismatch");
          return;
        }

        if (!CLIENT_ID || !ISSUER_BASE_URL) {
          res.writeHead(500, { "Content-Type": "text/html" });
          res.end(
            htmlPage({
              title: "Config missing",
              body: `<h1>❌ Missing config</h1><p>CLIENT_ID / ISSUER_BASE_URL not set. Check config.json.</p>`,
            })
          );
          sendStatus({ ok: false, message: "Missing config. Check config.json." });
          await emitSessionFromStore("config_missing");
          return;
        }

        // Exchange code for tokens
        const tokenResponse = await exchangeCodeForTokens({
          issuerBaseUrl: ISSUER_BASE_URL,
          clientId: CLIENT_ID,
          code,
          redirectUri: REDIRECT_URI,
          codeVerifier: pendingLogin.code_verifier,
        });

        const tokens = {
          access_token: tokenResponse.access_token,
          refresh_token: tokenResponse.refresh_token,
          id_token: tokenResponse.id_token,
          expires_at: computeExpiresAt({
            accessToken: tokenResponse.access_token,
            expiresIn: tokenResponse.expires_in,
          }),
          obtained_at: Date.now(),
          access_payload: decodeJwtPayload(tokenResponse.access_token),
        };

        await saveTokens(tokens);
        pendingLogin = null;

        sendStatus({
          ok: true,
          message: "Logged in! Tokens stored in macOS Keychain.",
          token_meta: { expires_at: tokens.expires_at, obtained_at: tokens.obtained_at },
          access_payload: tokens.access_payload,
        });
        sendSessionChanged({
          isLoggedIn: true,
          reason: "login_complete",
          tokenMeta: { expires_at: tokens.expires_at, obtained_at: tokens.obtained_at },
        });

        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(
          htmlPage({
            title: "Login complete",
            body: `<h1>✅ Login complete</h1><p>You’re signed in.</p>`,
          })
        );

        mainWindow?.show();
        mainWindow?.focus();
        return;
      }

      if (url.pathname === "/logged-out") {
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(
          htmlPage({
            title: "Logged out",
            body: `<h1>✅ Logged out</h1><p>You’re signed out.</p>`,
          })
        );
        await emitSessionFromStore("logged_out_callback");
        return;
      }

      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
    } catch (e) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Server error");
      sendStatus({ ok: false, message: "Loopback server error", details: String(e?.message || e) });
      await emitSessionFromStore("loopback_error");
    }
  });

  loopbackServer.listen(LOOPBACK_PORT, LOOPBACK_HOST, () => {
    console.log(`Loopback listening on http://${LOOPBACK_HOST}:${LOOPBACK_PORT}`);
  });

  loopbackServer.on("error", (err) => {
    sendStatus({
      ok: false,
      message: "Loopback server failed to start",
      details: String(err?.message || err),
    });
    sendSessionChanged({ isLoggedIn: false, reason: "loopback_server_error" });
  });
}

// -------------------- Token verification helper (used in get_tokens) --------------------

async function verifyAccessTokenOrThrow(accessToken) {
  if (!CLIENT_ID || !ISSUER_BASE_URL) throw new Error("Missing config (CLIENT_ID/ISSUER_BASE_URL).");

  const jwksUri = `${ISSUER_BASE_URL}/keys`;
  const verifyToken = makeVerifier({
    issuer: ISSUER_BASE_URL,
    audience: CLIENT_ID,
    jwksUri,
  });

  await verifyToken(accessToken);
}

// -------------------- App lifecycle --------------------

app.whenReady().then(async () => {
  await loadConfig();
  createWindow();
  startLoopbackServer();

  const existing = await loadTokens();
  sendStatus({
    ok: true,
    message: existing ? "Tokens found in Keychain" : "No tokens yet",
    token_meta: existing ? { expires_at: existing.expires_at, obtained_at: existing.obtained_at } : null,
  });
  await emitSessionFromStore("app_ready");
});

app.on("before-quit", () => {
  try {
    loopbackServer?.close();
  } catch {}
});

// -------------------- IPC APIs --------------------

ipcMain.handle("login", async () => {
  if (!CLIENT_ID) return { ok: false, message: "Missing CLIENT_ID. Set it in config.json." };
  if (!ISSUER_BASE_URL) return { ok: false, message: "Missing ISSUER_BASE_URL. Set it in config.json." };

  const { code_verifier, code_challenge } = makePkce();
  const state = crypto.randomBytes(16).toString("hex");
  pendingLogin = { state, code_verifier };

  const authorizeUrl = buildAuthorizeUrl({
    issuerBaseUrl: ISSUER_BASE_URL,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scope: SCOPES,
    state,
    codeChallenge: code_challenge,
    codeChallengeMethod: "S256",
  });

  await shell.openExternal(authorizeUrl);
  return { ok: true, authorizeUrl, redirect_uri: REDIRECT_URI };
});

ipcMain.handle("get_session", async () => {
  // Lightweight status endpoint for UI pill
  const t = await loadTokens();
  const isLoggedIn = Boolean(t?.access_token);
  return {
    ok: true,
    isLoggedIn,
    token_meta: t ? { expires_at: t.expires_at, obtained_at: t.obtained_at } : null,
  };
});

ipcMain.handle("get_tokens", async () => {
  const t = await loadTokens();
  if (!t) {
    await emitSessionFromStore("get_tokens_no_tokens");
    return { ok: false, message: "No tokens" };
  }

  if (!t.access_token) {
    await clearTokens();
    sendStatus({ ok: false, message: "Invalid session: missing access_token" });
    await emitSessionFromStore("missing_access_token");
    return { ok: false, message: "Invalid session: missing access_token" };
  }

  try {
    await verifyAccessTokenOrThrow(t.access_token);
  } catch (e) {
    // Tampered/expired token: clear and force logged out state
    await clearTokens();
    sendStatus({ ok: false, message: "Token validation failed", details: String(e?.message || e) });
    await emitSessionFromStore("token_validation_failed");
    return { ok: false, message: "Token validation failed" };
  }

  await emitSessionFromStore("get_tokens_ok");
  return { ok: true, tokens: t };
});

ipcMain.handle("refresh", async () => {
  if (!CLIENT_ID) return { ok: false, message: "Missing CLIENT_ID. Set it in config.json." };
  if (!ISSUER_BASE_URL) return { ok: false, message: "Missing ISSUER_BASE_URL. Set it in config.json." };

  const t = await loadTokens();
  if (!t?.refresh_token) {
    await emitSessionFromStore("refresh_no_refresh_token");
    return { ok: false, message: "No refresh_token" };
  }

  try {
    const refreshed = await refreshTokens({
      issuerBaseUrl: ISSUER_BASE_URL,
      clientId: CLIENT_ID,
      refreshToken: t.refresh_token,
    });

    const updated = {
      ...t,
      access_token: refreshed.access_token,
      refresh_token: refreshed.refresh_token || t.refresh_token,
      id_token: refreshed.id_token || t.id_token,
      expires_at: computeExpiresAt({
        accessToken: refreshed.access_token,
        expiresIn: refreshed.expires_in,
      }),
      obtained_at: Date.now(),
      access_payload: decodeJwtPayload(refreshed.access_token),
    };

    await saveTokens(updated);

    sendStatus({
      ok: true,
      message: "Refreshed! Updated tokens stored in Keychain.",
      token_meta: { expires_at: updated.expires_at, obtained_at: updated.obtained_at },
      access_payload: updated.access_payload,
    });

    sendSessionChanged({
      isLoggedIn: true,
      reason: "refresh_ok",
      tokenMeta: { expires_at: updated.expires_at, obtained_at: updated.obtained_at },
    });

    return {
      ok: true,
      message: "Refreshed! Updated tokens stored in Keychain.",
      token_meta: { expires_at: updated.expires_at, obtained_at: updated.obtained_at },
      access_payload: updated.access_payload,
    };
  } catch (e) {
    // If refresh fails, clear local tokens so UI becomes logged out
    await clearTokens();
    sendStatus({ ok: false, message: "Refresh failed", details: String(e?.message || e) });
    await emitSessionFromStore("refresh_failed");
    return { ok: false, message: "Refresh failed" };
  }
});

ipcMain.handle("logout", async () => {
  const t = await loadTokens();
  await clearTokens();

  // Update UI immediately
  sendSessionChanged({ isLoggedIn: false, reason: "logout_local" });

  if (t?.id_token && ISSUER_BASE_URL) {
    const logoutUrl = buildOidcLogoutUrl({
      issuerBaseUrl: ISSUER_BASE_URL,
      idTokenHint: t.id_token,
      postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI,
    });
    await shell.openExternal(logoutUrl);
  }

  return {
    ok: true,
    message: "Local tokens cleared. (Global logout opened in browser if id_token was present.)",
  };
});
