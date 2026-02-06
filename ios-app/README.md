# Example iOS App (iOS · Native)

This project only contains reference files you can use code snippets in your own iOS app.
It uses `ASWebAuthenticationSession` for OAuth Authorization Code + PKCE.

## Scalekit client setup (Mobile/Native client)
- Redirect URI: `exampleappmobile://callback`
- Initiate Login URI: `exampleappmobile://callback` (any app entrypoint is fine)
- Post-logout redirect URI: `exampleappmobile://logged-out`
- Scopes: `openid email profile offline_access`
- Enforce PKCE

## Configure client id
Edit `AuthService.swift`:
```swift
let clientId = "ntvc_..."
```

## Notes
- The redirect scheme is `exampleappmobile`.
- Update `issuerBaseURL` and `clientId` in `AuthService.swift`.
