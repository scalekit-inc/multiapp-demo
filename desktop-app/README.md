# Example Desktop App (Desktop · mac)

Electron desktop app that:
- Opens default browser for OAuth Authorization Code + PKCE
- Receives callback via custom URI scheme: `http://127.0.0.1:53682/callback`
- Exchanges code for tokens (no client_secret)
- Stores tokens in macOS Keychain (via `keytar`)
- Supports refresh and global logout (OIDC logout)

## Scalekit client setup (Desktop/Native client)
- Redirect URI: `http://127.0.0.1:53682/callback`
- Post-logout redirect URI: `http://127.0.0.1:53682/logged-out`
- Scopes: `openid email profile offline_access`
- Enforce PKCE

## Configure client id
Edit `config.json`:
```json
{ "client_id": "ntvc_..." }
```

## Run (dev)
```bash
npm install
npm start
```

### Gatekeeper note
Unsigned local DMGs/apps can trigger warnings:
- right click the app → Open
- or System Settings → Privacy & Security → Open Anyway

For real distribution, you should codesign + notarize.
