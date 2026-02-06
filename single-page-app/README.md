# Example Web App (local)

Example SPA (Single Page App)

A browser-only Single Page Application that demonstrates:
- OAuth Authorization Code + PKCE with Scalekit
- No backend server (pure frontend)
- Tokens stored in sessionStorage
- Refresh-on-demand middleware
- Client-side JWT verification
- OIDC logout redirect

## Prereqs
- Node.js 18+

## Scalekit client config
- Redirect URI: `http://localhost:5174/callback`
- Initiate Login URI: `http://localhost:5174/dashboard` // it doesn't take effect yet, any entrypoint for your app should be sufficient
- Post logout redirect URI: `http://localhost:5174/logged-out`
- Scopes should include: `openid email profile offline_access`
- PKCE: Required (S256)

## Run
```bash
cp .env.example .env
# edit .env with CLIENT_ID and CLIENT_SECRET
npm install
npm run dev
```

Open:
- http://localhost:5174

## Notes
- Access token payload is decoded for display.
