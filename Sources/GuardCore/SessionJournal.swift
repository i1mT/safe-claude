import Darwin
import Foundation

/// Persists process birth identity plus fixed DNS protocol-state labels needed
/// to detect an encrypted-to-cleartext transition after an Agent restart.
/// Environment, arguments, credentials, project paths, resolver addresses and
/// query contents are excluded.
public struct SessionRecord: Codable, Equatable, Sendable {
    public let pid: pid_t
    public let uid: uid_t
    public let startSeconds: UInt64
    public let startMicroseconds: UInt64
    public let executable: String
    public let isTopLevel: Bool
    public let encryptedDNSDomains: Set<String>
    public let downgradedDNSDomains: Set<String>
    public init(identity: ProcessIdentity, executable: String, isTopLevel: Bool = false) {
        pid = identity.pid; uid = identity.uid; startSeconds = identity.startSeconds
        startMicroseconds = identity.startMicroseconds; self.executable = executable; self.isTopLevel = isTopLevel
        encryptedDNSDomains = []
        downgradedDNSDomains = []
    }
    private enum CodingKeys: String, CodingKey {
        case pid, uid, startSeconds, startMicroseconds, executable, isTopLevel
        case encryptedDNSDomains, downgradedDNSDomains
    }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        pid = try values.decode(pid_t.self, forKey: .pid)
        uid = try values.decode(uid_t.self, forKey: .uid)
        startSeconds = try values.decode(UInt64.self, forKey: .startSeconds)
        startMicroseconds = try values.decode(UInt64.self, forKey: .startMicroseconds)
        executable = try values.decode(String.self, forKey: .executable)
        isTopLevel = try values.decodeIfPresent(Bool.self, forKey: .isTopLevel) ?? false
        encryptedDNSDomains = try values.decodeIfPresent(Set<String>.self, forKey: .encryptedDNSDomains) ?? []
        downgradedDNSDomains = try values.decodeIfPresent(Set<String>.self, forKey: .downgradedDNSDomains) ?? []
    }
    public func matches(_ identity: ProcessIdentity) -> Bool {
        matchesProcess(identity) && identity.executable == executable
    }
    /// Process birth identity survives exec; the executable can legitimately
    /// still be the launcher when the agent crashes between ticket and exec.
    public func matchesProcess(_ identity: ProcessIdentity) -> Bool {
        identity.pid == pid && identity.uid == uid && identity.startSeconds == startSeconds &&
        identity.startMicroseconds == startMicroseconds
    }
    fileprivate func updatingDNSProtection(encrypted: Set<String>,
                                           downgraded: Set<String>) -> SessionRecord {
        SessionRecord(pid: pid, uid: uid, startSeconds: startSeconds,
            startMicroseconds: startMicroseconds, executable: executable,
            isTopLevel: isTopLevel, encryptedDNSDomains: encrypted,
            downgradedDNSDomains: downgraded)
    }
    private init(pid: pid_t, uid: uid_t, startSeconds: UInt64, startMicroseconds: UInt64,
                 executable: String, isTopLevel: Bool, encryptedDNSDomains: Set<String>,
                 downgradedDNSDomains: Set<String>) {
        self.pid = pid
        self.uid = uid
        self.startSeconds = startSeconds
        self.startMicroseconds = startMicroseconds
        self.executable = executable
        self.isTopLevel = isTopLevel
        self.encryptedDNSDomains = encryptedDNSDomains
        self.downgradedDNSDomains = downgradedDNSDomains
    }
}

public actor SessionJournal {
    private let path: String
    private var records: [SessionRecord]
    public init(path: String) throws {
        self.path = path
        try GuardIPC.prepareDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            guard errno == ENOENT else { throw GuardIPCError.system(errno) }
            records = []; return
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == getuid(),
              (info.st_mode & 0o077) == 0, info.st_size <= 65_536 else { throw GuardIPCError.invalidPath }
        let data = try BoundedFile.read(fd, maximum: 65_536)
        let value = try JSONDecoder().decode([SessionRecord].self, from: data)
        guard value.count <= 128, value.allSatisfy({ $0.pid > 1 && $0.uid == getuid() &&
            $0.executable.hasPrefix("/") && !$0.executable.utf8.contains(0) &&
            $0.encryptedDNSDomains.allSatisfy(DNSPathEvidence.DomainClass.allRawValues.contains) &&
            $0.downgradedDNSDomains.allSatisfy(DNSPathEvidence.DomainClass.allRawValues.contains) }) else {
            throw GuardIPCError.invalidMessage
        }
        records = value
    }
    public func all() -> [SessionRecord] { records }
    public func add(_ record: SessionRecord) throws {
        guard record.pid > 1, record.uid == getuid(), record.executable.hasPrefix("/"),
              !record.executable.utf8.contains(0), records.count < 128,
              !records.contains(where: { $0.pid == record.pid }) else { throw GuardIPCError.invalidMessage }
        let previous = records
        records.append(record)
        do { try persist() } catch { records = previous; throw error }
    }
    public func remove(_ record: SessionRecord) throws {
        let previous = records
        records.removeAll {
            $0.pid == record.pid && $0.uid == record.uid &&
                $0.startSeconds == record.startSeconds &&
                $0.startMicroseconds == record.startMicroseconds
        }
        do { try persist() } catch { records = previous; throw error }
    }
    /// Stores only fixed DNS domain classes and protocol-state transitions,
    /// bound to the existing PID birth identity in the session journal.
    public func observeDNSProtection(_ evidence: DNSPathEvidence) throws -> Bool? {
        guard let index = records.firstIndex(where: {
            $0.pid == evidence.pid && $0.startSeconds == evidence.processStartSeconds &&
                $0.startMicroseconds == evidence.processStartMicroseconds
        }) else { return nil }
        let domain = evidence.domainClass.rawValue
        var encrypted = records[index].encryptedDNSDomains
        var downgraded = records[index].downgradedDNSDomains
        let oldEncrypted = encrypted
        let oldDowngraded = downgraded
        switch evidence.resolverSecurity {
        case .encrypted, .dnsOverHTTPS, .dnsOverTLS:
            encrypted.insert(domain)
        case .cleartext:
            if encrypted.contains(domain) { downgraded.insert(domain) }
        case .unknown, .none:
            break
        }
        guard encrypted != oldEncrypted || downgraded != oldDowngraded else {
            return downgraded.contains(domain)
        }
        let previous = records[index]
        let updated = previous.updatingDNSProtection(encrypted: encrypted, downgraded: downgraded)
        records[index] = updated
        do { try persist() } catch { records[index] = previous; throw error }
        return downgraded.contains(domain)
    }
    private func persist() throws {
        let data = try JSONEncoder().encode(records)
        guard data.count <= 65_536 else { throw GuardIPCError.invalidMessage }
        let temporary = path + "." + UUID().uuidString + ".tmp"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(fd); unlink(temporary) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw GuardIPCError.system(errno) }
                offset += n
            }
        }
        guard fsync(fd) == 0, rename(temporary, path) == 0 else { throw GuardIPCError.system(errno) }
    }
}

private extension DNSPathEvidence.DomainClass {
    static var allRawValues: Set<String> { Set(allCases.map(\.rawValue)) }
}
