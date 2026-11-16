import Darwin
import Foundation

/// Facts about this process and the local system at one instant. This snapshot
/// does not describe a different process unless its environment was supplied.
public struct LocalEnvironmentSnapshot: Equatable, Sendable {
    public enum ProxyRoute: Equatable, Sendable {
        case notEvaluated
        case direct(reason: String)
        case configured(scheme: String, sourceKey: String, source: String, hasCredentials: Bool)
        case unknown(reason: String)
    }

    public let collectedAt: Date
    public let systemTimeZoneIdentifier: String?
    public let systemLocaleIdentifier: String?
    public let systemRegionCode: String?
    public let preferredLanguages: [String]
    /// Only validated locale values are retained. Invalid or empty values are
    /// represented by their keys in `invalidProcessLocaleKeys`.
    public let processLocale: [String: String]
    public let invalidProcessLocaleKeys: [String]
    public let processTimeZoneIdentifier: String?
    public let processTimeZoneIsInvalid: Bool
    public let processTimeZoneConsistency: Consistency
    public let processLanguageConsistency: Consistency
    /// Names only: proxy URLs, bypass lists and credentials are never retained.
    public let presentProxyKeys: [String]
    public let conflictingProxyKeys: [String]
    public let proxyRoute: ProxyRoute
    public let proxyTargetHost: String?
    public let proxyTargetPort: Int?
    /// Only the dangerous value is retained; absence cannot prove settings
    /// scopes did not override the launch environment.
    public let explicitlyDisablesTLSVerification: Bool
    /// Host-wide Hypervisor.framework guest signal. Nil means the kernel
    /// could not provide a well-formed answer.
    public let isVirtualized: Bool?
    /// Indicates a structurally valid OpenSSH session marker. No address,
    /// port, or terminal path is retained.
    public let hasRemoteShellContext: Bool

    private static let localeKeys = ["LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE"]
    private static let proxyKeys = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY",
                                    "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"]
    private static let remoteShellKeys = ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]

    /// Captures only allowlisted environment variables via getenv. Supply a
    /// target to evaluate proxy configuration; this is not a network probe.
    public static func capture(targetHost: String? = nil, targetPort: Int = 443) -> Self {
        var environment: [String: String] = [:]
        for key in localeKeys + proxyKeys + remoteShellKeys + ["TZ", "NODE_TLS_REJECT_UNAUTHORIZED"] {
            if let pointer = getenv(key) { environment[key] = String(cString: pointer) }
        }
        return capture(environment: environment, targetHost: targetHost, targetPort: targetPort)
    }

    /// Captures a caller-provided launch environment, without retaining it.
    /// The caller is responsible for supplying the environment of the process
    /// whose configuration is being examined.
    public static func capture(environment: [String: String], targetHost: String? = nil,
                               targetPort: Int = 443) -> Self {
        collect(environment: environment, systemTimeZone: systemTimeZone(),
                systemLocale: .current, preferredLanguages: Locale.preferredLanguages,
                targetHost: targetHost, targetPort: targetPort, collectedAt: Date(),
                isVirtualized: runtimeVirtualizationStatus())
    }

    /// Internal injection point for deterministic tests. The input dictionary
    /// is never stored; callers may pass a launch context without persisting it.
    static func collect(environment: [String: String], systemTimeZone: TimeZone?,
                        systemLocale: Locale, preferredLanguages: [String],
                        targetHost: String? = nil, targetPort: Int = 443,
                        collectedAt: Date, isVirtualized: Bool? = false,
                        hasRemoteShellContext: Bool? = nil) -> Self {
        var locales: [String: String] = [:]
        var invalidKeys: [String] = []
        for key in localeKeys {
            guard let value = environment[key] else { continue }
            if validLocale(value) { locales[key] = value } else { invalidKeys.append(key) }
        }
        let validLanguages = preferredLanguages.filter(validLocale)
        let explicitTZ = environment["TZ"]
        let zone = explicitTZ.flatMap { value -> TimeZone? in
            guard value.utf8.count <= 128, value.utf8.allSatisfy({
                (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) ||
                [43, 45, 46, 47, 95].contains($0)
            }) else { return nil }
            return TimeZone(identifier: value)
        }
        let tzInvalid = explicitTZ != nil && zone == nil
        let timeConsistency: Consistency
        if tzInvalid || systemTimeZone == nil {
            timeConsistency = .unknown
        } else {
            timeConsistency = EnvironmentConsistency.processTimeZone(
                environment: zone.map { ["TZ": $0.identifier] } ?? [:],
                system: systemTimeZone!, at: collectedAt)
        }
        // An invalid higher-priority locale must not fall through to a lower one.
        let languageKeys = ["LC_ALL", "LC_MESSAGES", "LANG"]
        let firstNonempty = languageKeys.first { !(environment[$0] ?? "").isEmpty }
        let languageConsistency: Consistency
        if let key = firstNonempty, locales[key] == nil {
            languageConsistency = .unknown
        } else {
            languageConsistency = EnvironmentConsistency.processLanguage(environment: locales,
                                                                        preferredLanguages: validLanguages)
        }
        let route: ProxyRoute
        if let targetHost {
            switch ProxyConfiguration.resolve(targetHost: targetHost, targetPort: targetPort, environment: environment) {
            case .direct(let reason): route = .direct(reason: reason)
            case .unknown(let reason): route = .unknown(reason: reason)
            case .proxy(let proxy):
                route = .configured(scheme: proxy.scheme, sourceKey: proxy.sourceKey,
                                    source: proxy.source, hasCredentials: proxy.hasCredentials)
            }
        } else {
            route = .notEvaluated
        }
        let localeID = systemLocale.identifier
        let region = systemLocale.region?.identifier
        let remoteShellContext = hasRemoteShellContext ??
            Self.detectRemoteShellContext(environment: environment)
        return Self(collectedAt: collectedAt, systemTimeZoneIdentifier: systemTimeZone?.identifier,
                    systemLocaleIdentifier: validLocale(localeID) ? localeID : nil,
                    systemRegionCode: region.flatMap { validRegion($0) ? $0 : nil },
                    preferredLanguages: validLanguages, processLocale: locales,
                    invalidProcessLocaleKeys: invalidKeys, processTimeZoneIdentifier: zone?.identifier,
                    processTimeZoneIsInvalid: tzInvalid, processTimeZoneConsistency: timeConsistency,
                    processLanguageConsistency: languageConsistency,
                    presentProxyKeys: proxyKeys.filter { environment[$0] != nil },
                    conflictingProxyKeys: ProxyConfiguration.conflictingKeys(environment: environment),
                    proxyRoute: route,
                    proxyTargetHost: targetHost?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                    proxyTargetPort: targetHost == nil ? nil : targetPort,
                    explicitlyDisablesTLSVerification: environment["NODE_TLS_REJECT_UNAUTHORIZED"] == "0",
                    isVirtualized: isVirtualized,
                    hasRemoteShellContext: remoteShellContext)
    }

    // Foundation's TimeZone.current is affected by this process's TZ. Read
    // the macOS system zone separately so launch overrides can be compared.
    private static func systemTimeZone() -> TimeZone? {
        guard let link = try? FileManager.default.destinationOfSymbolicLink(atPath: "/etc/localtime") else { return nil }
        let prefix = "/var/db/timezone/zoneinfo/"
        guard link.hasPrefix(prefix) else { return nil }
        return TimeZone(identifier: String(link.dropFirst(prefix.count)))
    }

    static func parseVirtualizationStatus(value: Int32, size: Int, result: Int32) -> Bool? {
        guard result == 0, size == MemoryLayout<Int32>.size, value == 0 || value == 1 else {
            return nil
        }
        return value == 1
    }

    private static func runtimeVirtualizationStatus() -> Bool? {
        #if os(macOS)
        var value: Int32 = -1
        var size = MemoryLayout<Int32>.size
        let result = sysctlbyname("kern.hv_vmm_present", &value, &size, nil, 0)
        return parseVirtualizationStatus(value: value, size: size, result: result)
        #else
        return nil
        #endif
    }

    static func detectRemoteShellContext(environment: [String: String]) -> Bool {
        if let value = environment["SSH_CONNECTION"], value.utf8.count <= 256 {
            let fields = value.split(whereSeparator: \.isWhitespace)
            if fields.count == 4,
               IPAddress.bytes(String(fields[0])) != nil,
               validPort(fields[1]), IPAddress.bytes(String(fields[2])) != nil,
               validPort(fields[3]) {
                return true
            }
        }
        if let value = environment["SSH_CLIENT"], value.utf8.count <= 192 {
            let fields = value.split(whereSeparator: \.isWhitespace)
            if fields.count == 3,
               IPAddress.bytes(String(fields[0])) != nil,
               validPort(fields[1]), validPort(fields[2]) {
                return true
            }
        }
        if let value = environment["SSH_TTY"], value.utf8.count <= 128,
           value.hasPrefix("/dev/"),
           value.utf8.allSatisfy({ byte in
               (48...57).contains(byte) || (65...90).contains(byte) ||
               (97...122).contains(byte) || [45, 46, 47, 95].contains(byte)
           }) {
            return true
        }
        return false
    }

    private static func validPort(_ token: Substring) -> Bool {
        guard !token.isEmpty, token.utf8.count <= 5,
              token.utf8.allSatisfy({ (48...57).contains($0) }),
              let port = UInt16(token), port > 0 else { return false }
        return true
    }

    private static func validLocale(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else { return false }
        // Restrict accepted values to locale syntax, avoiding arbitrary text in snapshots.
        let pattern = #"^(?:[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*|C|POSIX)(?:\.[A-Za-z0-9_-]{1,16})?$"#
        return value.range(of: pattern, options: .regularExpression) != nil
    }

    private static func validRegion(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return (bytes.count == 2 && bytes.allSatisfy { (65...90).contains($0) }) ||
               (bytes.count == 3 && bytes.allSatisfy { (48...57).contains($0) })
    }
}
