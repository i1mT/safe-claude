import CryptoKit
import Foundation

/// Opaque, process-local cache identity for observations that depend on an
/// outbound route. Original routing values are used transiently, then erased
/// from the lookup surface behind a keyed digest.
enum RouteBoundCacheIdentity {
    static func make(ip: String, apiKey: String? = nil,
                     environment: [String: String], settings: [String: String],
                     using key: SymmetricKey) -> Data? {
        var value: [String: Any] = [
            "ip": ip,
            "environment": environment,
            "settings": settings
        ]
        if let apiKey { value["apiKey"] = apiKey }
        guard let encoded = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else {
            return nil
        }
        return Data(HMAC<SHA256>.authenticationCode(for: encoded, using: key))
    }
}
