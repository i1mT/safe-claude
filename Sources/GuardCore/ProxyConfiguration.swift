import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Only a redacted description of proxy configuration may leave the caller.
public struct ProxyDescription: Codable, Equatable, Sendable {
    public let scheme: String
    public let host: String
    public let port: Int
    public let hasCredentials: Bool
    public let sourceKey: String
    public let source: String

    public init(scheme: String, host: String, port: Int, hasCredentials: Bool, sourceKey: String, source: String) {
        self.scheme = scheme
        self.host = host
        self.port = port
        self.hasCredentials = hasCredentials
        self.sourceKey = sourceKey
        self.source = source
    }
}

public enum ProxyDecision: Equatable, Sendable {
    case direct(reason: String)
    case proxy(ProxyDescription)
    case unknown(reason: String)
}

/// Resolves a deliberately limited subset of Claude Code network settings.
/// Unsupported bypass syntax is unknown, not an implicit direct connection.
public enum ProxyConfiguration {
    private static let proxyKeys = ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"]
    private static let caseVariantProxyKeyPairs = [
        ("https_proxy", "HTTPS_PROXY"),
        ("http_proxy", "HTTP_PROXY"),
        ("all_proxy", "ALL_PROXY"),
        ("no_proxy", "NO_PROXY"),
    ]

    public static func resolve(
        targetHost: String,
        targetPort: Int = 443,
        environment: [String: String],
        settingsEnvironment: [String: String] = [:]
    ) -> ProxyDecision {
        let host = targetHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty, (1...65535).contains(targetPort) else {
            return .unknown(reason: "INVALID_TARGET")
        }

        // The local Claude 2.1.319 fixture shows user settings can override
        // the same process variable. Until all settings scopes and HTTPS are
        // verified, conflicting sources must not be guessed.
        for key in proxyKeys + ["all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"] {
            if let process = environment[key], let setting = settingsEnvironment[key], process != setting {
                return .unknown(reason: "SETTINGS_ENV_CONFLICT")
            }
        }

        // The official Claude documentation does not establish ALL_PROXY
        // semantics. Until the actual runtime is verified, its presence cannot
        // safely be classified as direct or as the selected HTTP proxy.
        if ["all_proxy", "ALL_PROXY"].contains(where: {
            value(for: $0, environment: environment, settings: settingsEnvironment) != nil
        }) {
            return .unknown(reason: "ALL_PROXY_UNVERIFIED")
        }

        let lowerNoProxy = value(for: "no_proxy", environment: environment, settings: settingsEnvironment)
        let upperNoProxy = value(for: "NO_PROXY", environment: environment, settings: settingsEnvironment)
        if let lowerNoProxy, let upperNoProxy, lowerNoProxy.value != upperNoProxy.value {
            return .unknown(reason: "NO_PROXY_CONFLICT")
        }
        if let bypass = lowerNoProxy ?? upperNoProxy, !bypass.value.isEmpty {
            switch matchesNoProxy(bypass.value, host: host, port: targetPort) {
            case .matches:
                return .direct(reason: "NO_PROXY")
            case .unsupported:
                return .unknown(reason: "NO_PROXY_UNSUPPORTED")
            case .noMatch:
                break
            }
        }

        for key in proxyKeys {
            guard let selected = value(for: key, environment: environment, settings: settingsEnvironment) else {
                continue
            }
            guard !selected.value.isEmpty else {
                return .unknown(reason: "EMPTY_PROXY_VALUE")
            }
            guard let components = URLComponents(string: selected.value),
                  let scheme = components.scheme?.lowercased(),
                  let proxyHost = components.host, !proxyHost.isEmpty,
                  components.path.isEmpty || components.path == "/",
                  components.query == nil, components.fragment == nil else {
                return .unknown(reason: "INVALID_PROXY_URL")
            }
            guard scheme == "http" || scheme == "https" else {
                return .unknown(reason: "UNSUPPORTED_PROXY_SCHEME")
            }
            let port = components.port ?? (scheme == "https" ? 443 : 80)
            guard (1...65535).contains(port) else {
                return .unknown(reason: "INVALID_PROXY_PORT")
            }
            return .proxy(ProxyDescription(
                scheme: scheme,
                host: proxyHost,
                port: port,
                hasCredentials: components.user != nil || components.password != nil,
                sourceKey: key,
                source: selected.source
            ))
        }
        return .direct(reason: "NO_PROXY_CONFIGURED")
    }

    /// Returns only variable names, never their potentially sensitive values.
    /// Keep conflict evidence even when precedence selects one of the values.
    public static func conflictingKeys(
        environment: [String: String],
        settingsEnvironment: [String: String] = [:]
    ) -> [String] {
        var conflicts: [String] = []
        for (lower, upper) in caseVariantProxyKeyPairs {
            guard let a = value(for: lower, environment: environment, settings: settingsEnvironment),
                  let b = value(for: upper, environment: environment, settings: settingsEnvironment),
                  a.value != b.value else { continue }
            conflicts.append(contentsOf: [lower, upper])
        }
        return conflicts
    }

    private static func value(
        for key: String,
        environment: [String: String],
        settings: [String: String]
    ) -> (value: String, source: String)? {
        if let value = environment[key] { return (value, "environment") }
        if let value = settings[key] { return (value, "settings") }
        return nil
    }

    private enum Match {
        case matches, noMatch, unsupported
    }

    private static func matchesNoProxy(_ raw: String, host: String, port: Int) -> Match {
        let entries = raw.split { $0 == "," || $0.isWhitespace }
        var hasUnsupported = false
        let targetAddress = ipBytes(host)
        for entry in entries {
            let token = String(entry).lowercased()
            if token == "*" { return .matches }
            if token.contains("*") {
                hasUnsupported = true
                continue
            }
            if token.contains("/") {
                let pieces = token.split(separator: "/", omittingEmptySubsequences: false)
                guard pieces.count == 2, let network = ipBytes(String(pieces[0])),
                      let prefix = Int(pieces[1]),
                      (0...(network.count * 8)).contains(prefix) else {
                    hasUnsupported = true
                    continue
                }
                guard let targetAddress else {
                    hasUnsupported = true
                    continue
                }
                if network.count == targetAddress.count && address(targetAddress, belongsTo: network, prefix: prefix) {
                    return .matches
                }
                continue
            }
            if token.hasPrefix("[") {
                guard let close = token.firstIndex(of: "]") else {
                    hasUnsupported = true
                    continue
                }
                let addressText = String(token[token.index(after: token.startIndex)..<close])
                let remainder = token[token.index(after: close)...]
                let expectedPort: Int?
                if remainder.isEmpty {
                    expectedPort = nil
                } else if remainder.first == ":", let parsed = Int(remainder.dropFirst()),
                          (1...65535).contains(parsed) {
                    expectedPort = parsed
                } else {
                    hasUnsupported = true
                    continue
                }
                guard let entryAddress = ipBytes(addressText), entryAddress.count == 16 else {
                    hasUnsupported = true
                    continue
                }
                if expectedPort.map({ $0 != port }) == true { continue }
                if targetAddress == entryAddress { return .matches }
                continue
            }
            let pieces = token.split(separator: ":", omittingEmptySubsequences: false)
            guard pieces.count <= 2, let domainPart = pieces.first, !domainPart.isEmpty else {
                hasUnsupported = true
                continue
            }
            if pieces.count == 2 {
                guard let expectedPort = Int(pieces[1]), (1...65535).contains(expectedPort) else {
                    hasUnsupported = true
                    continue
                }
                if expectedPort != port { continue }
            }
            if let entryAddress = ipBytes(String(domainPart)) {
                if targetAddress == entryAddress { return .matches }
                continue
            }
            let domain = domainPart.hasPrefix(".") ? String(domainPart.dropFirst()) : String(domainPart)
            if host == domain || host.hasSuffix("." + domain) { return .matches }
        }
        return hasUnsupported ? .unsupported : .noMatch
    }

    private static func ipBytes(_ value: String) -> [UInt8]? {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return withUnsafeBytes(of: &ipv4) { Array($0) }
        }
        var ipv6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            return withUnsafeBytes(of: &ipv6) { Array($0) }
        }
        return nil
    }

    private static func address(_ target: [UInt8], belongsTo network: [UInt8], prefix: Int) -> Bool {
        guard target.count == network.count else { return false }
        let fullBytes = prefix / 8
        let remainingBits = prefix % 8
        if fullBytes > 0, !target[..<fullBytes].elementsEqual(network[..<fullBytes]) {
            return false
        }
        guard remainingBits > 0 else { return true }
        let mask = UInt8(0xff << (8 - remainingBits))
        return target[fullBytes] & mask == network[fullBytes] & mask
    }
}
