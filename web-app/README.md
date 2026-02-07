# Example Web App (local)

An Express + EJS webapp that demonstrates:
- OAuth Authorization Code flow with Scalekit
- Server-side token storage (session cookie in browser; tokens stay on server)
- Refresh-on-demand middleware
- Client-side JWT verification
- OIDC logout redirect

## Prereqs
- Node.js 18+

## Scalekit client config
- Redirect URI: `http://localhost:8081/callback`
- Initiate Login URI: `http://localhost:8081/dashboard` // this is required for auth flows to work without intruption.
- Post logout redirect URI: `http://localhost:8081/logged-out`
- Scopes should include: `openid email profile offline_access`

## Run
```bash
cp .env.example .env
# edit .env with CLIENT_ID and CLIENT_SECRET
npm install
npm start
```

Open:
- http://localhost:8081

## Notes
- Access token payload is decoded for display.
