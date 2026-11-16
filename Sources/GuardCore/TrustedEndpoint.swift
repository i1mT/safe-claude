import Foundation

/// Credential-free HTTPS origin used by the local endpoint trust policy.
public enum TrustedEndpoint {
    private static func isValidDNSName(_ host: String) -> Bool {
        guard !host.isEmpty, host.utf8.count <= 253, !host.hasSuffix(".") else { return false }
        return host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            guard (1...63).contains(label.utf8.count),
                  let first = label.utf8.first, let last = label.utf8.last,
                  first.isASCIIAlphanumeric, last.isASCIIAlphanumeric else { return false }
            return label.utf8.allSatisfy { $0.isASCIIAlphanumeric || $0 == 45 }
        }
    }

    public static func canonicalOrigin(_ raw: String) -> String? {
        guard raw.utf8.count <= 2048,
              let components = URLComponents(string: raw),
              components.scheme?.lowercased() == "https",
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              let host = components.host?.lowercased(), isValidDNSName(host),
              components.port.map({ (1...65535).contains($0) }) ?? true else { return nil }
        let path = components.percentEncodedPath
        guard path.isEmpty || path == "/" else { return nil }
        return "https://\(host)\(components.port.map { $0 == 443 ? "" : ":\($0)" } ?? "")"
    }

    public static func isTrusted(_ raw: String, allowlist: [String]) -> Bool {
        guard let origin = canonicalOrigin(raw) else { return false }
        if origin == "https://api.anthropic.com" { return true }
        return allowlist.contains { canonicalOrigin($0) == origin }
    }
}

private extension UInt8 {
    var isASCIIAlphanumeric: Bool {
        (48...57).contains(self) || (97...122).contains(self)
    }
}
