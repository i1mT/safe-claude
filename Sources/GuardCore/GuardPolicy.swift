import Darwin
import Foundation

public struct GuardPolicy: Codable, Sendable, Equatable {
    public static let maximumFileSize = 16 * 1024
    public let version: Int
    public var minimumScore: Int
    public var runtimeMinimumScore: Int
    public var allowIPWho: Bool
    public var allowProxyCheck: Bool
    public var enableUDPCheck: Bool
    public var stunEndpoint: String
    public var forceTerminate: Bool
    public var dnsRequiredProtocol: DNSRequiredProtocol
    public var notificationsEnabled: Bool
    public var trustedEndpoints: [String]
    public init(minimumScore: Int = 80, runtimeMinimumScore: Int = 80, allowIPWho: Bool = false,
                allowProxyCheck: Bool = false,
                enableUDPCheck: Bool = false, stunEndpoint: String = STUNProbe.defaultEndpoint,
                forceTerminate: Bool = false,
                dnsRequiredProtocol: DNSRequiredProtocol = .anyEncrypted,
                notificationsEnabled: Bool = false, trustedEndpoints: [String] = []) {
        version = 1; self.minimumScore = minimumScore; self.runtimeMinimumScore = runtimeMinimumScore
        self.allowIPWho = allowIPWho
        self.allowProxyCheck = allowProxyCheck
        self.enableUDPCheck = enableUDPCheck
        self.stunEndpoint = stunEndpoint
        self.forceTerminate = forceTerminate
        self.dnsRequiredProtocol = dnsRequiredProtocol
        self.notificationsEnabled = notificationsEnabled
        self.trustedEndpoints = trustedEndpoints.map {
            TrustedEndpoint.canonicalOrigin($0) ?? $0
        }.uniqued().sorted()
    }
    private enum CodingKeys: String, CodingKey {
        case version, minimumScore, runtimeMinimumScore, allowIPWho, allowProxyCheck, enableUDPCheck
        case stunEndpoint, forceTerminate, dnsRequiredProtocol, notificationsEnabled, trustedEndpoints
    }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        minimumScore = try container.decode(Int.self, forKey: .minimumScore)
        runtimeMinimumScore = try container.decode(Int.self, forKey: .runtimeMinimumScore)
        allowIPWho = try container.decodeIfPresent(Bool.self, forKey: .allowIPWho) ?? false
        allowProxyCheck = try container.decodeIfPresent(Bool.self, forKey: .allowProxyCheck) ?? false
        enableUDPCheck = try container.decodeIfPresent(Bool.self, forKey: .enableUDPCheck) ?? false
        stunEndpoint = try container.decodeIfPresent(String.self, forKey: .stunEndpoint) ?? STUNProbe.defaultEndpoint
        forceTerminate = try container.decodeIfPresent(Bool.self, forKey: .forceTerminate) ?? false
        dnsRequiredProtocol = try container.decodeIfPresent(DNSRequiredProtocol.self,
                                                             forKey: .dnsRequiredProtocol) ?? .anyEncrypted
        notificationsEnabled = try container.decodeIfPresent(Bool.self, forKey: .notificationsEnabled) ?? false
        trustedEndpoints = try container.decodeIfPresent([String].self, forKey: .trustedEndpoints) ?? []
    }
    public var isValid: Bool {
        version == 1 && (0...100).contains(minimumScore) && (0...100).contains(runtimeMinimumScore) &&
        STUNProbe.validate(endpoint: stunEndpoint) != nil &&
        trustedEndpoints.count <= 32 && Set(trustedEndpoints).count == trustedEndpoints.count &&
        trustedEndpoints.allSatisfy { TrustedEndpoint.canonicalOrigin($0) == $0 }
    }
    /// Whether an existing managed session still has the scoring inputs and
    /// runtime decision threshold it was assessed against.
    public func hasSameRuntimeAssessment(as other: GuardPolicy) -> Bool {
        runtimeMinimumScore == other.runtimeMinimumScore &&
        allowIPWho == other.allowIPWho &&
        allowProxyCheck == other.allowProxyCheck &&
        enableUDPCheck == other.enableUDPCheck &&
        stunEndpoint == other.stunEndpoint &&
        dnsRequiredProtocol == other.dnsRequiredProtocol &&
        trustedEndpoints == other.trustedEndpoints
    }
    public static var path: String { GuardIPC.directory + "/policy.json" }
    public static func load(path: String = path) throws -> GuardPolicy {
        try GuardIPC.prepareDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 { if errno == ENOENT { return GuardPolicy() }; throw GuardIPCError.system(errno) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), (info.st_mode & 0o077) == 0,
              info.st_size <= maximumFileSize else {
            throw GuardIPCError.invalidPath
        }
        let data = try BoundedFile.read(fd, maximum: maximumFileSize)
        let policy = try JSONDecoder().decode(GuardPolicy.self, from: data)
        guard policy.isValid else { throw GuardIPCError.invalidMessage }
        return policy
    }
    public func save(path: String = path) throws {
        guard isValid else { throw GuardIPCError.invalidMessage }
        let data = try JSONEncoder().encode(self)
        guard data.count <= Self.maximumFileSize else { throw GuardIPCError.invalidMessage }
        try GuardIPC.prepareDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        let tmp = path + "." + UUID().uuidString + ".tmp"
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(fd); unlink(tmp) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw GuardIPCError.system(errno) }
                offset += n
            }
        }
        guard fsync(fd) == 0, rename(tmp, path) == 0 else { throw GuardIPCError.system(errno) }
    }
}

private extension Sequence where Element: Hashable {
    func uniqued() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}
