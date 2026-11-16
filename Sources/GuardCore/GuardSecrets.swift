import Foundation
import LocalAuthentication
import Security

/// The provider key is stored in the user's Keychain, never in policy files,
/// launch arguments, diagnostics, or IPC messages.
public enum GuardSecrets {
    private static let proxyCheckService = "local.safeclaude.proxycheck"
    private static let ipAPIService = "local.safeclaude.ipapi"
    private static let account = "api-key"
    public static func readProxyCheckKey() throws -> String? {
        try readKey(service: proxyCheckService)
    }
    public static func readIPAPIKey() throws -> String? {
        try readKey(service: ipAPIService)
    }
    private static func readKey(service: String) throws -> String? {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              let key = String(data: data, encoding: .utf8), !key.isEmpty else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        return key
    }
    public static func saveProxyCheckKey(_ key: String) throws {
        // Reuse the request validator before storing a malformed key.
        _ = try ProxyCheckV3.request(ip: "192.0.2.1", apiKey: key)
        try saveKey(key, service: proxyCheckService)
    }
    public static func saveIPAPIKey(_ key: String) throws {
        _ = try IPAPIAdapter.makeRequest(ip: "192.0.2.1", apiKey: key)
        try saveKey(key, service: ipAPIService)
    }
    private static func saveKey(_ key: String, service: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account]
        let attributes: [String: Any] = [kSecValueData as String: Data(key.utf8)]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var insert = query
            insert[kSecValueData as String] = Data(key.utf8)
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let added = SecItemAdd(insert as CFDictionary, nil)
            guard added == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(added)) }
        } else if status != errSecSuccess {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }
    public static func deleteProxyCheckKey() throws {
        try deleteKey(service: proxyCheckService)
    }
    public static func deleteIPAPIKey() throws {
        try deleteKey(service: ipAPIService)
    }
    private static func deleteKey(service: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }
    /// A local random HMAC key, unrelated to Claude or provider credentials.
    public static func historyKey() throws -> Data {
        let context = LAContext()
        context.interactionNotAllowed = true
        let lookup: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "local.safeclaude.history", kSecAttrAccount as String: "hmac-key",
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data, data.count == 32 { return data }
        guard status == errSecItemNotFound else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        var bytes = [UInt8](repeating: 0, count: 32)
        let randomStatus = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard randomStatus == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(randomStatus)) }
        let insert: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "local.safeclaude.history", kSecAttrAccount as String: "hmac-key",
            kSecValueData as String: Data(bytes), kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecUseAuthenticationContext as String: context]
        let added = SecItemAdd(insert as CFDictionary, nil)
        if added == errSecDuplicateItem { return try historyKey() }
        guard added == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(added)) }
        return Data(bytes)
    }
}
