import dotenv from "dotenv";
import express from "express";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";
import {
  buildAuthorizeUrl,
  buildOidcLogoutUrl,
  computeExpiresAt,
  decodeJwtPayload,
  exchangeCodeForTokens,
  generateState,
  refreshTokens
} from "./auth/oauth.js";
import { makeJwtVerifier } from "./auth/verify.js";


dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const {
  PORT = "8081",
  APP_ORIGIN,
  ISSUER_BASE_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  SCOPES,
  SESSION_SECRET,
} = process.env;

if (!APP_ORIGIN || !ISSUER_BASE_URL || !CLIENT_ID || !CLIENT_SECRET || !SCOPES || !SESSION_SECRET) {
  throw new Error("Missing required env vars. Check .env");
}

const REDIRECT_URI = `${APP_ORIGIN}/callback`;

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
  session({
    name: "primary.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      // secure should be true in production HTTPS. For local http, keep false.
      secure: false,
    },
  })
);

const verifyJwt = makeJwtVerifier({
  issuerBaseUrl: ISSUER_BASE_URL,
  audience: CLIENT_ID,
});

app.get("/", (req, res) => {
  const tokens = req.session?.tokens;
  if (tokens?.access_token) {
    try {
      verifyJwt(tokens.access_token);
    } catch (e) {
      return res.status(400).render("error", {
        title: "Invalid token",
        message: "Token signature/claims validation failed.",
        details: String(e),
      });
    }
  }
  if (!tokens?.access_token) {
    return res.render("logged_out", {
      appOrigin: APP_ORIGIN,
      issuerBaseUrl: ISSUER_BASE_URL,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      scopes: SCOPES,
    });
  }

  return res.render("home", {
    appOrigin: APP_ORIGIN,
    issuerBaseUrl: ISSUER_BASE_URL,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scopes: SCOPES,
    tokens,
  });
});

app.get("/login", (req, res) => {
  const state = generateState();
  req.session.oauth_state = state;

  const authorizeUrl = buildAuthorizeUrl({
    issuerBaseUrl: ISSUER_BASE_URL,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scope: SCOPES,
    state,
  });

  return res.redirect(authorizeUrl);
});

app.get("/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).render("error", {
        title: "OAuth error",
        message: `${error}: ${error_description || ""}`,
        details: "",
      });
    }

    if (!code || typeof code !== "string") {
      return res.status(400).render("error", {
        title: "Missing code",
        message: "No authorization code returned.",
        details: "",
      });
    }

    if (!state || typeof state !== "string" || state !== req.session.oauth_state) {
      return res.status(400).render("error", {
        title: "Invalid state",
        message: "State mismatch. Please retry login.",
        details: "",
      });
    }

    const tokenResponse = await exchangeCodeForTokens({
      issuerBaseUrl: ISSUER_BASE_URL,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      code,
      redirectUri: REDIRECT_URI,
    });

    req.session.tokens = {
      access_token: tokenResponse.access_token,
      refresh_token: tokenResponse.refresh_token,
      id_token: tokenResponse.id_token, // used for OIDC logout
      token_type: tokenResponse.token_type,
      scope: tokenResponse.scope,
      expires_at: computeExpiresAt({
        accessToken: tokenResponse.access_token,
        expiresIn: tokenResponse.expires_in,
      }),
      obtained_at: Date.now(),
      access_payload: decodeJwtPayload(tokenResponse.access_token),
    };

    delete req.session.oauth_state;

    return res.redirect("/");
  } catch (e) {
    return res.status(500).render("error", {
      title: "Callback failed",
      message: "Token exchange failed.",
      details: e?.details ? JSON.stringify(e.details, null, 2) : String(e),
    });
  }
});

app.post("/token/refresh", async (req, res) => {
  try {
    const tokens = req.session?.tokens;
    if (!tokens?.refresh_token) {
      return res.status(401).json({ error: "No refresh_token in session" });
    }

    const refreshed = await refreshTokens({
      issuerBaseUrl: process.env.ISSUER_BASE_URL,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: tokens.refresh_token,
    });

    // Preserve old refresh_token if provider doesn't return a new one
    const nextRefreshToken = refreshed.refresh_token || tokens.refresh_token;

    const accessPayload = decodeJwtPayload(refreshed.access_token);
    const expiresAt = computeExpiresAt({
      accessToken: refreshed.access_token,
      expiresIn: refreshed.expires_in,
    });

    req.session.tokens = {
      ...tokens,
      ...refreshed,
      refresh_token: nextRefreshToken,
      access_payload: accessPayload,
      obtained_at: Date.now(),
      expires_at: expiresAt,
    };

    return res.json({
      ok: true,
      expires_at: req.session.tokens.expires_at,
      obtained_at: req.session.tokens.obtained_at,
    });
  } catch (err) {
    console.log(err)
    req.session.destroy(() => {
      return res.status(401).json({
        ok: false,
        error: "Token refresh failed",
        redirect_to: "/",
      });
    });
  }
});


/**
 * Global logout:
 * - Clears local session
 * - Redirects to auth server /oidc/logout with id_token_hint + post_logout_redirect_uri
 * - Auth server ends its session and redirects back to /logged-out
 */
app.get("/logout", (req, res) => {
  const tokens = req.session?.tokens;
  const idToken = tokens?.id_token;
  const postLogoutRedirectUri = `${APP_ORIGIN}/logged-out`;

  req.session.destroy(() => {
    if (!idToken) {
      // If no id_token is available, do a local-only logout success page.
      return res.redirect("/logged-out");
    }

    const logoutUrl = buildOidcLogoutUrl({
      issuerBaseUrl: ISSUER_BASE_URL,
      idTokenHint: idToken,
      postLogoutRedirectUri,
    });

    return res.redirect(logoutUrl);
  });
});

app.get("/logged-out", (req, res) => {
  return res.render("logged_out_success", { appOrigin: APP_ORIGIN });
});

app.listen(Number(PORT), "0.0.0.0", () => {
  console.log(`Example Web App running at ${APP_ORIGIN}`);
  console.log(`Callback: ${REDIRECT_URI}`);
});
