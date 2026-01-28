import Foundation
import AuthenticationServices
import UIKit

@MainActor
final class AuthService: NSObject, ObservableObject {
    // ---- Config ----
    let issuerBaseURL = URL(string: "https://yourcompany.scalekit.dev")!

    // TODO: set your Native/Mobile client id here:
    let clientId = "ntvc_123"

    let redirectScheme = "exampleappmobile"
    let redirectURI = "exampleappmobile://callback"
    let postLogoutRedirectURI = "exampleappmobile://logged-out"
    let scope = "openid email profile offline_access"

    // ---- State ----
    @Published var status: String = "Logged out"
    @Published var accessPayload: String = ""
    @Published var expiresAt: Date? = nil

    private var authSession: ASWebAuthenticationSession?
    private var pendingVerifier: String? = nil
    private var pendingState: String? = nil

    private let keychain = KeychainStore(service: "com.example.mobile.Example")
    private let refreshAccount = "refresh_token"
    private let idTokenAccount = "id_token"
    private let accessTokenAccount = "access_token"
    private let expiresAtAccount = "expires_at"

    func bootstrap() {
        // Load existing tokens if any
        do {
            if let access = try keychain.get(account: accessTokenAccount),
               let exp = try keychain.get(account: expiresAtAccount),
               let expStr = String(data: exp, encoding: .utf8),
               let expTime = TimeInterval(expStr) {
                let dt = Date(timeIntervalSince1970: expTime)
                self.expiresAt = dt
                self.status = dt > Date() ? "Logged in (token cached)" : "Token expired (refresh available)"
                self.accessPayload = decodeJwtPayload(String(data: access, encoding: .utf8) ?? "")
            }
        } catch {
            self.status = "Bootstrap error: \(error)"
        }
    }

    func login() {
        let verifier = PKCE.randomURLSafeString(length: 64)
        let challenge = PKCE.codeChallenge(for: verifier)
        let state = PKCE.randomURLSafeString(length: 16)

        pendingVerifier = verifier
        pendingState = state

        var url = URLComponents(url: issuerBaseURL.appendingPathComponent("/oauth/authorize"), resolvingAgainstBaseURL: false)!
        url.queryItems = [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: clientId),
            .init(name: "redirect_uri", value: redirectURI),
            .init(name: "scope", value: scope),
            .init(name: "state", value: state),
            .init(name: "code_challenge", value: challenge),
            .init(name: "code_challenge_method", value: "S256")
        ]

        guard let authURL = url.url else { return }

        let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: redirectScheme) { [weak self] callbackURL, error in
            Task { @MainActor in
                if let error = error {
                    self?.status = "Login cancelled/failed: \(error.localizedDescription)"
                    return
                }
                guard let callbackURL = callbackURL else {
                    self?.status = "No callback URL"
                    return
                }
                await self?.handleCallback(callbackURL)
            }
        }

        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false // best-effort SSO
        authSession = session

        _ = session.start()
        status = "Opening login..."
    }

    private func handleCallback(_ callbackURL: URL) async {
        guard let comps = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let items = comps.queryItems else {
            status = "Invalid callback URL"
            return
        }

        let code = items.first(where: { $0.name == "code" })?.value
        let state = items.first(where: { $0.name == "state" })?.value
        let err = items.first(where: { $0.name == "error" })?.value

        if let err = err {
            status = "OAuth error: \(err)"
            return
        }

        guard let code = code else {
            status = "Missing code"
            return
        }

        guard let expectedState = pendingState, state == expectedState else {
            status = "State mismatch"
            return
        }

        guard let verifier = pendingVerifier else {
            status = "Missing PKCE verifier"
            return
        }

        do {
            let token = try await exchangeCodeForTokens(code: code, verifier: verifier)
            try persistTokens(token)
            status = "Logged in ✅"
        } catch {
            status = "Token exchange failed: \(error)"
        }

        // Swift equivalent of finally
        pendingVerifier = nil
        pendingState = nil
    }

    func refresh(force: Bool = false) async {
        do {
            guard let exp = expiresAt else {
                status = "No expiresAt, cannot refresh"
                return
            }

            if !force, exp.timeIntervalSinceNow > 60 {
                status = "Token still valid (no refresh needed)"
                return
            }

            guard let refreshData = try keychain.get(account: refreshAccount),
                  let refreshToken = String(data: refreshData, encoding: .utf8) else {
                status = "No refresh_token in Keychain"
                return
            }

            let token = try await refreshTokens(refreshToken: refreshToken)
            try persistTokens(token)
            status = "Refreshed ✅"
        } catch {
            status = "Refresh failed: \(error)"
        }
    }

    func logout() {
        Task { @MainActor in
            do {
                let idTokenData = try keychain.get(account: idTokenAccount)
                try keychain.delete(account: refreshAccount)
                try keychain.delete(account: idTokenAccount)
                try keychain.delete(account: accessTokenAccount)
                try keychain.delete(account: expiresAtAccount)
                self.expiresAt = nil
                self.accessPayload = ""
                self.status = "Logged out (local) ✅"

                // Global logout (best effort)
                if let idTokenData = idTokenData,
                   let idToken = String(data: idTokenData, encoding: .utf8) {
                    openGlobalLogout(idTokenHint: idToken)
                }
            } catch {
                self.status = "Logout error: \(error)"
            }
        }
    }

    private func openGlobalLogout(idTokenHint: String) {
        var url = URLComponents(url: issuerBaseURL.appendingPathComponent("/oidc/logout"), resolvingAgainstBaseURL: false)!
        url.queryItems = [
            .init(name: "id_token_hint", value: idTokenHint),
            .init(name: "post_logout_redirect_uri", value: postLogoutRedirectURI)
        ]

        guard let logoutURL = url.url else { return }

        let session = ASWebAuthenticationSession(url: logoutURL, callbackURLScheme: redirectScheme) { [weak self] callbackURL, error in
            Task { @MainActor in
                if let error = error {
                    self?.status = "Logout (global) finished with: \(error.localizedDescription)"
                    return
                }
                if callbackURL != nil {
                    self?.status = "Logged out (global) ✅"
                }
            }
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false
        authSession = session
        _ = session.start()
    }

    // ---- HTTP ----

    private struct TokenResponse: Decodable {
        let access_token: String
        let refresh_token: String?
        let id_token: String?
        let expires_in: Int?
        let token_type: String?
        let scope: String?
    }

    private func exchangeCodeForTokens(code: String, verifier: String) async throws -> TokenResponse {
        let url = issuerBaseURL.appendingPathComponent("/oauth/token")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        var body = URLComponents()
        body.queryItems = [
            .init(name: "grant_type", value: "authorization_code"),
            .init(name: "client_id", value: clientId),
            .init(name: "code", value: code),
            .init(name: "redirect_uri", value: redirectURI),
            .init(name: "code_verifier", value: verifier)
        ]
        req.httpBody = body.percentEncodedQuery?.data(using: .utf8)

        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        guard (200..<300).contains(http.statusCode) else {
            throw NSError(domain: "token_exchange", code: http.statusCode, userInfo: ["body": String(data: data, encoding: .utf8) ?? ""])
        }

        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    private func refreshTokens(refreshToken: String) async throws -> TokenResponse {
        let url = issuerBaseURL.appendingPathComponent("/oauth/token")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        var body = URLComponents()
        body.queryItems = [
            .init(name: "grant_type", value: "refresh_token"),
            .init(name: "client_id", value: clientId),
            .init(name: "refresh_token", value: refreshToken)
        ]
        req.httpBody = body.percentEncodedQuery?.data(using: .utf8)

        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        guard (200..<300).contains(http.statusCode) else {
            throw NSError(domain: "token_refresh", code: http.statusCode, userInfo: ["body": String(data: data, encoding: .utf8) ?? ""])
        }

        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    // ---- Persist / Decode ----

    private func persistTokens(_ token: TokenResponse) throws {
        try keychain.set(Data(token.access_token.utf8), account: accessTokenAccount)

        if let rt = token.refresh_token {
            try keychain.set(Data(rt.utf8), account: refreshAccount)
        }

        if let idt = token.id_token {
            try keychain.set(Data(idt.utf8), account: idTokenAccount)
        }

        let exp = computeExpiresAt(accessToken: token.access_token, expiresIn: token.expires_in)
        self.expiresAt = exp
        try keychain.set(Data(String(exp.timeIntervalSince1970).utf8), account: expiresAtAccount)

        self.accessPayload = decodeJwtPayload(token.access_token)
    }

    private func computeExpiresAt(accessToken: String, expiresIn: Int?) -> Date {
        if let s = expiresIn {
            return Date().addingTimeInterval(TimeInterval(s))
        }
        // fallback: parse JWT exp
        if let exp = jwtExp(accessToken) {
            return Date(timeIntervalSince1970: exp)
        }
        return Date().addingTimeInterval(300)
    }

    private func jwtExp(_ jwt: String) -> TimeInterval? {
        guard let payload = jwtPayload(jwt) else { return nil }
        return payload["exp"] as? TimeInterval
    }

    private func decodeJwtPayload(_ jwt: String) -> String {
        guard let payload = jwtPayload(jwt) else { return "" }
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted]),
           let s = String(data: data, encoding: .utf8) {
            return s
        }
        return ""
    }

    private func jwtPayload(_ jwt: String) -> [String: Any]? {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        let b64 = String(parts[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let padded = b64 + String(repeating: "=", count: (4 - b64.count % 4) % 4)
        guard let data = Data(base64Encoded: padded) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}

extension AuthService: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { ($0 as? UIWindowScene)?.keyWindow }
            .first ?? ASPresentationAnchor()
    }
}

private extension UIWindowScene {
    var keyWindow: UIWindow? {
        self.windows.first(where: { $0.isKeyWindow })
    }
}
