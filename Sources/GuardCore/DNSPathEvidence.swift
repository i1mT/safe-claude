import CryptoKit
import Darwin
import Foundation

/// A normalized resolver endpoint held only in process memory. It is never
/// encoded into the shared evidence spool.
public struct DNSResolverEndpoint: Hashable, Sendable {
    public let host: String
    public let port: UInt16
    /// Optional TLS authentication name from the active resolver configuration.
    /// It is transient and deliberately excluded from serialized path evidence.
    public let tlsServerName: String?
    public let identity: String
    public let digest: String

    public init?(host: String, port: UInt16, tlsServerName: String? = nil) {
        guard let identity = DNSPathEvidence.resolverIdentity(host: host, port: port),
              let separator = identity.lastIndex(of: "|"),
              let parsedPort = UInt16(identity[identity.index(after: separator)...]) else { return nil }
        let normalizedServerName: String?
        if let tlsServerName {
            let name = tlsServerName.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            guard !name.isEmpty, name.utf8.count <= 253,
                  name.split(separator: ".").allSatisfy({ label in
                      !label.isEmpty && label.utf8.count <= 63 &&
                      label.first != "-" && label.last != "-" &&
                      label.utf8.allSatisfy {
                          (97...122).contains($0) || (48...57).contains($0) || $0 == 45
                      }
                  }) else { return nil }
            normalizedServerName = name
        } else {
            normalizedServerName = nil
        }
        self.host = String(identity[..<separator])
        self.port = parsedPort
        self.tlsServerName = normalizedServerName
        self.identity = identity
        digest = DNSPathEvidence.digest(identity)
    }
}

/// A minimized record of a protected DNS flow. Query names and packet contents
/// are intentionally excluded; `domainClass` is a fixed allowlisted label.
public struct DNSPathEvidence: Codable, Equatable, Sendable {
    public enum ResolverVerdict: Equatable, Sendable {
        case matchesConfiguredPath
        case bypassesConfiguredPath
        case unknown
    }
    public enum DomainClass: String, Codable, Sendable, CaseIterable {
        case anthropicAPI, claudeWeb
    }
    public enum Transport: String, Codable, Sendable {
        case udp, tcp
    }
    public enum ResolverSecurity: String, Codable, Sendable {
        /// Legacy spool value from releases that did not distinguish DoH/DoT.
        case encrypted
        case dnsOverHTTPS
        case dnsOverTLS
        case cleartext
        case unknown
    }

    public let pid: pid_t
    public let pidVersion: Int32
    public let processStartSeconds: UInt64
    public let processStartMicroseconds: UInt64
    public let domainClass: DomainClass
    public let transport: Transport
    /// Protocol from the active NetworkExtension DNS settings that apply to
    /// this queried domain. This is configuration evidence, not packet data.
    public let resolverSecurity: ResolverSecurity?
    /// SHA-256 of a normalized resolver endpoint, never the endpoint itself.
    public let resolverDigest: String
    /// Country result only; the recursive egress IP is discarded before the
    /// short-lived spool record is written.
    public let resolverCountryCode: String?
    public let resolverCountryResolverDigest: String?
    public let resolverCountryObservedAt: Date?
    public let observedAt: Date

    public init(pid: pid_t, pidVersion: Int32, processStartSeconds: UInt64,
                processStartMicroseconds: UInt64, domainClass: DomainClass,
                transport: Transport, resolverIdentity: String,
                resolverSecurity: ResolverSecurity = .unknown,
                resolverCountryCode: String? = nil, resolverCountryResolverIdentity: String? = nil,
                resolverCountryObservedAt: Date? = nil,
                observedAt: Date = Date()) {
        self.pid = pid
        self.pidVersion = pidVersion
        self.processStartSeconds = processStartSeconds
        self.processStartMicroseconds = processStartMicroseconds
        self.domainClass = domainClass
        self.transport = transport
        self.resolverSecurity = resolverSecurity
        self.resolverDigest = Self.digest(resolverIdentity)
        self.resolverCountryCode = resolverCountryCode
        self.resolverCountryResolverDigest = resolverCountryCode == nil
            ? nil : Self.digest(resolverCountryResolverIdentity ?? resolverIdentity)
        self.resolverCountryObservedAt = resolverCountryCode == nil
            ? nil : (resolverCountryObservedAt ?? observedAt)
        self.observedAt = observedAt
    }

    public func carryingResolverCountry(_ country: String, resolverIdentity: String,
                                        observedAt countryAt: Date) -> Self {
        Self(pid: pid, pidVersion: pidVersion, processStartSeconds: processStartSeconds,
             processStartMicroseconds: processStartMicroseconds, domainClass: domainClass,
             transport: transport, resolverSecurity: resolverSecurity,
             resolverDigest: resolverDigest, resolverCountryCode: country,
             resolverCountryResolverDigest: Self.digest(resolverIdentity),
             resolverCountryObservedAt: countryAt, observedAt: observedAt)
    }

    public func carryingResolverCountry(from previous: Self) -> Self {
        guard let country = previous.resolverCountryCode,
              let digest = previous.resolverCountryResolverDigest,
              let countryAt = previous.resolverCountryObservedAt else { return self }
        return Self(pid: pid, pidVersion: pidVersion, processStartSeconds: processStartSeconds,
            processStartMicroseconds: processStartMicroseconds, domainClass: domainClass,
            transport: transport, resolverSecurity: resolverSecurity,
            resolverDigest: resolverDigest, resolverCountryCode: country,
            resolverCountryResolverDigest: digest,
            resolverCountryObservedAt: countryAt, observedAt: observedAt)
    }

    private init(pid: pid_t, pidVersion: Int32, processStartSeconds: UInt64,
                 processStartMicroseconds: UInt64, domainClass: DomainClass,
                 transport: Transport, resolverSecurity: ResolverSecurity?,
                 resolverDigest: String, resolverCountryCode: String?,
                 resolverCountryResolverDigest: String?,
                 resolverCountryObservedAt: Date?, observedAt: Date) {
        self.pid = pid
        self.pidVersion = pidVersion
        self.processStartSeconds = processStartSeconds
        self.processStartMicroseconds = processStartMicroseconds
        self.domainClass = domainClass
        self.transport = transport
        self.resolverSecurity = resolverSecurity
        self.resolverDigest = resolverDigest
        self.resolverCountryCode = resolverCountryCode
        self.resolverCountryResolverDigest = resolverCountryResolverDigest
        self.resolverCountryObservedAt = resolverCountryObservedAt
        self.observedAt = observedAt
    }

    public static func digest(_ resolverIdentity: String) -> String {
        SHA256.hash(data: Data(resolverIdentity.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    public static func isLiteralAddress(_ value: String) -> Bool {
        IPAddress.bytes(value) != nil
    }

    public static func resolverIdentity(host: String, port: UInt16) -> String? {
        guard port > 0, host.utf8.count <= 253, !host.utf8.contains(0) else { return nil }
        let unwrapped = host.hasPrefix("[") && host.hasSuffix("]")
            ? String(host.dropFirst().dropLast()) : host
        let normalized: String
        var v4 = in_addr()
        if unwrapped.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            var output = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &v4, &output, socklen_t(output.count)) != nil else { return nil }
            normalized = Self.stringFromCBuffer(output)
        } else {
            var v6 = in6_addr()
            if unwrapped.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
                var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                guard inet_ntop(AF_INET6, &v6, &output, socklen_t(output.count)) != nil else { return nil }
                normalized = Self.stringFromCBuffer(output)
            } else {
                let name = unwrapped.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
                guard !name.isEmpty,
                      name.utf8.allSatisfy({
                          (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 46
                      }) else { return nil }
                normalized = name
            }
        }
        return "\(normalized)|\(port)"
    }

    private static func stringFromCBuffer(_ buffer: [CChar]) -> String {
        String(decoding: buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
               as: UTF8.self)
    }

    public func matches(_ current: ProcessIdentity, session: SessionRecord,
                        now: Date = Date()) -> Bool {
        let age = now.timeIntervalSince(observedAt)
        return (0...DNSPathEvidenceSpool.maximumAge).contains(age) &&
            pidVersion > 0 && session.matches(current) &&
            pid == session.pid && pid == current.pid &&
            processStartSeconds == session.startSeconds &&
            processStartSeconds == current.startSeconds &&
            processStartMicroseconds == session.startMicroseconds &&
            processStartMicroseconds == current.startMicroseconds
    }

    public func resolverVerdict(configuredResolverDigests: Set<String>?) -> ResolverVerdict {
        guard let configuredResolverDigests, !configuredResolverDigests.isEmpty else { return .unknown }
        return configuredResolverDigests.contains(resolverDigest)
            ? .matchesConfiguredPath : .bypassesConfiguredPath
    }
}

public enum DNSRequiredProtocol: String, Codable, Sendable, CaseIterable {
    case anyEncrypted
    case dnsOverHTTPS
    case dnsOverTLS

    public func accepts(_ security: DNSPathEvidence.ResolverSecurity) -> Bool {
        switch (self, security) {
        case (.anyEncrypted, .encrypted), (.anyEncrypted, .dnsOverHTTPS), (.anyEncrypted, .dnsOverTLS),
             (.dnsOverHTTPS, .dnsOverHTTPS), (.dnsOverTLS, .dnsOverTLS):
            true
        default:
            false
        }
    }
}

public enum DNSResolverProbeConsent {
    private static let key = "allowIPWhoResolverEgress"

    public static func setAllowed(_ allowed: Bool) {
        guard let defaults = UserDefaults(suiteName: DNSPathEvidenceSpool.appGroup) else { return }
        defaults.set(allowed, forKey: key)
        _ = defaults.synchronize()
    }

    public static var isAllowed: Bool {
        UserDefaults(suiteName: DNSPathEvidenceSpool.appGroup)?.bool(forKey: key) == true
    }
}

/// Small App Group spool shared by the DNS System Extension and per-user Agent.
/// A single advisory lock serializes append/drain, including extension restarts.
public struct DNSPathEvidenceSpool: Sendable {
    public static let appGroup = "group.com.safeclaude.shared"
    public static let maximumRecords = 128
    public static let maximumAge: TimeInterval = 30
    private let path: String

    public init(containerURL: URL) {
        path = containerURL.appendingPathComponent("dns-path-evidence.json").path
    }

    public static func shared() -> DNSPathEvidenceSpool? {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroup
        ) else { return nil }
        return DNSPathEvidenceSpool(containerURL: container)
    }

    public func append(_ evidence: DNSPathEvidence) throws {
        try withRecords { records in
            var next = records.filter { Date().timeIntervalSince($0.observedAt) >= 0 &&
                Date().timeIntervalSince($0.observedAt) <= Self.maximumAge }
            next.append(evidence)
            if next.count > Self.maximumRecords {
                next.removeFirst(next.count - Self.maximumRecords)
            }
            return next
        }
    }

    /// Drains only fresh records; malformed, oversized, or unsafe spool files
    /// fail closed and are never interpreted as evidence.
    public func drain(now: Date = Date()) throws -> [DNSPathEvidence] {
        var drained: [DNSPathEvidence] = []
        try withRecords { records in
            drained = records.filter {
                let age = now.timeIntervalSince($0.observedAt)
                return (0...Self.maximumAge).contains(age)
            }
            return []
        }
        return drained
    }

    private func withRecords(_ update: ([DNSPathEvidence]) throws -> [DNSPathEvidence]) throws {
        let lockPath = path + ".lock"
        let lockFD = open(lockPath, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lockFD >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(lockFD) }
        var lockInfo = stat()
        guard fstat(lockFD, &lockInfo) == 0, (lockInfo.st_mode & S_IFMT) == S_IFREG,
              lockInfo.st_uid == getuid(), (lockInfo.st_mode & 0o077) == 0,
              flock(lockFD, LOCK_EX) == 0 else { throw GuardIPCError.invalidPath }
        defer { _ = flock(lockFD, LOCK_UN) }

        var records: [DNSPathEvidence] = []
        let input = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if input >= 0 {
            defer { close(input) }
            var info = stat()
            guard fstat(input, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
                  info.st_uid == getuid(), (info.st_mode & 0o077) == 0,
                  info.st_size <= 65_536 else { throw GuardIPCError.invalidPath }
            if info.st_size > 0 {
                let data = try BoundedFile.read(input, maximum: 65_536)
                records = try JSONDecoder().decode([DNSPathEvidence].self, from: data)
                guard records.count <= Self.maximumRecords,
                      records.allSatisfy(Self.isValid) else { throw GuardIPCError.invalidMessage }
            }
        } else if errno != ENOENT {
            throw GuardIPCError.system(errno)
        }

        let updated = try update(records)
        guard updated.count <= Self.maximumRecords else { throw GuardIPCError.invalidMessage }
        let data = try JSONEncoder().encode(updated)
        guard data.count <= 65_536 else { throw GuardIPCError.invalidMessage }
        let temporary = path + "." + UUID().uuidString + ".tmp"
        let output = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard output >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(output); unlink(temporary) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(output, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw GuardIPCError.system(errno) }
                offset += count
            }
        }
        guard fsync(output) == 0, rename(temporary, path) == 0 else {
            throw GuardIPCError.system(errno)
        }
    }

    private static func isValid(_ value: DNSPathEvidence) -> Bool {
        value.pid > 1 && value.pidVersion > 0 &&
            value.resolverDigest.count == 64 &&
            value.resolverDigest.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } &&
            (value.resolverCountryCode == nil ||
                (value.resolverCountryCode!.utf8.count == 2 &&
                 value.resolverCountryCode!.utf8.allSatisfy { (65...90).contains($0) })) &&
            (value.resolverCountryResolverDigest == nil ||
                (value.resolverCountryResolverDigest!.count == 64 &&
                 value.resolverCountryResolverDigest!.utf8.allSatisfy {
                     (48...57).contains($0) || (97...102).contains($0)
                 })) &&
            (value.resolverCountryCode == nil ||
                value.resolverCountryObservedAt?.timeIntervalSince1970.isFinite == true) &&
            value.observedAt.timeIntervalSince1970.isFinite
    }
}
