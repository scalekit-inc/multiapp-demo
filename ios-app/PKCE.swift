//
//  PKCE.swift
//
//  Created by Scalekit on 23/01/26.
//

import Foundation
import CryptoKit

struct PKCE {
    static func randomURLSafeString(length: Int = 64) -> String {
        var bytes = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64urlEncodedString()
    }

    static func codeChallenge(for verifier: String) -> String {
        let data = Data(verifier.utf8)
        let hash = SHA256.hash(data: data)
        return Data(hash).base64urlEncodedString()
    }
}

private extension Data {
    func base64urlEncodedString() -> String {
        let b64 = self.base64EncodedString()
        return b64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
