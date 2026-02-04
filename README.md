# Scalekit OAuth Demo Apps

This repository contains a set of **example applications** demonstrating how OAuth / OIDC flows vary across different application types — **while all sharing the same authenticated user session**.

The apps are intentionally built as **independent clients** (web, SPA, desktop, and mobile), but when logged in through Scalekit, they participate in **single sign-on (SSO)** via a common identity session.

The focus is on showing how **trust boundaries, token handling, PKCE, and storage models** differ based on where the app runs — not on duplicating login state per app.

## What this repo demonstrates

- OAuth flow differences across app types
- Multi-application **single sign-on (SSO)** using a shared identity session
- Where client secrets are allowed vs forbidden
- Why PKCE is required for public clients
- Token storage patterns across server, browser, desktop, and mobile
- Refresh and logout behavior across apps

## Applications

### Web App (Server-Rendered)
**Directory:** `web-app/`

- Express + EJS web application
- OAuth Authorization Code flow **with client secret**
- Tokens stored only on the server
- Browser receives a session cookie
- Refresh handled server-side
- Participates in shared SSO session
- OIDC logout redirect supported

### Single Page App (SPA)
**Directory:** `spa/`

- Browser-only Single Page Application
- OAuth Authorization Code **with PKCE**
- No client secret
- Tokens stored in browser storage
- Client-side refresh and JWT verification
- Participates in shared SSO session
- OIDC logout redirect supported

### Desktop App (macOS)
**Directory:** `desktop-app/`

- Electron-based desktop application
- System browser used for authentication
- Authorization Code + PKCE
- Localhost redirect for callback handling
- Tokens stored securely in macOS Keychain
- Participates in shared SSO session
- Supports refresh and global logout

### iOS App
**Directory:** `ios-app/`

- Native iOS application
- Uses system browser (`ASWebAuthenticationSession`)
- Authorization Code + PKCE
- Custom URL scheme callback
- Tokens stored securely in iOS Keychain
- Participates in shared SSO session

## Prerequisites

- A Scalekit account
- OAuth clients configured per app type  
  (redirect URIs and PKCE requirements vary)

Each application directory contains a README with exact setup steps and client configuration details.

## Notes

- These are **demo / reference apps**, not production templates
- UX and error handling are intentionally minimal
- JWTs are decoded for visibility and debugging only
