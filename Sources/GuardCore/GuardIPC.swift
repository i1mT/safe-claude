import Darwin
import Foundation

public struct GuardRequest: Codable, Sendable {
    public let version: Int
    public let action: String
    public let environment: [String: String]?
    public let executable: String?
    public let workingDirectory: String?
    public let additionalSettingsPath: String?
    public let commandLineSettings: SelectiveSettings.Findings?
    /// Transient proxy settings from inline --settings; excluded from Findings
    /// so unrelated Claude settings and authentication values never cross IPC.
    public let commandLineRoutingEnvironment: [String: String]?
    public let commandLineRoutingConflict: Bool?
    /// A fixed, credential-free authentication method label.
    public let authenticationContext: String?
    public let customEndpointPresent: Bool?
    public let ticket: String?
    public let entryKind: String?
    public let sessionPID: pid_t?
    public let sessionStartSeconds: UInt64?
    public let sessionStartMicroseconds: UInt64?
    public let failureSessionDigest: String?
    public let failureKind: String?
    public init(action: String, environment: [String: String]? = nil, executable: String? = nil,
                workingDirectory: String? = nil,
                additionalSettingsPath: String? = nil,
                commandLineSettings: SelectiveSettings.Findings? = nil,
                commandLineRoutingEnvironment: [String: String]? = nil,
                commandLineRoutingConflict: Bool? = nil,
                authenticationContext: String? = nil,
                customEndpointPresent: Bool? = nil, ticket: String? = nil, entryKind: String? = nil,
                sessionPID: pid_t? = nil, sessionStartSeconds: UInt64? = nil,
                sessionStartMicroseconds: UInt64? = nil,
                failureSessionDigest: String? = nil, failureKind: String? = nil) {
        version = 1; self.action = action; self.environment = environment; self.executable = executable
        self.workingDirectory = workingDirectory
        self.additionalSettingsPath = additionalSettingsPath
        self.commandLineSettings = commandLineSettings
        self.commandLineRoutingEnvironment = commandLineRoutingEnvironment
        self.commandLineRoutingConflict = commandLineRoutingConflict
        self.authenticationContext = authenticationContext
        self.customEndpointPresent = customEndpointPresent
        self.ticket = ticket
        self.entryKind = entryKind
        self.sessionPID = sessionPID
        self.sessionStartSeconds = sessionStartSeconds
        self.sessionStartMicroseconds = sessionStartMicroseconds
        self.failureSessionDigest = failureSessionDigest
        self.failureKind = failureKind
    }
}
public struct GuardFinding: Codable, Sendable {
    public let rule: String
    public let points: Int
    public init(rule: String, points: Int) { self.rule = rule; self.points = points }
}
public enum GuardAssessmentContext: String, Codable, Sendable {
    case agentDefault = "agent-default"
    case claudeLaunch = "claude-launch"
    case managedSession = "managed-session"
}
public struct GuardResponse: Codable, Sendable {
    public let version: Int
    public let decision: String
    public let safetyScore: Int?
    public let scoreUpperBound: Int?
    public let unknownCount: Int
    /// Rule identifiers only; never includes environment values or IPs.
    public let unknownRules: [String]?
    public let reason: String
    public let findings: [GuardFinding]
    public let ruleStatuses: [RuleReportStatus]?
    public let assessmentContext: GuardAssessmentContext?
    public let checkedAt: Date
    public let expiresAt: Date?
    public let ticket: String?
    public let managedSessions: Int?
    public let sessions: [GuardSessionSummary]?
    public init(decision: String, safetyScore: Int? = nil, scoreUpperBound: Int? = nil,
                unknownCount: Int = 0, unknownRules: [String]? = nil, reason: String, findings: [GuardFinding] = [],
                ruleStatuses: [RuleReportStatus]? = nil,
                assessmentContext: GuardAssessmentContext? = nil,
                checkedAt: Date = Date(), expiresAt: Date? = nil, ticket: String? = nil,
                managedSessions: Int? = nil, sessions: [GuardSessionSummary]? = nil) {
        version = 1; self.decision = decision; self.safetyScore = safetyScore
        self.scoreUpperBound = scoreUpperBound; self.unknownCount = unknownCount; self.unknownRules = unknownRules; self.reason = reason
        self.findings = findings; self.ruleStatuses = ruleStatuses
        self.assessmentContext = assessmentContext
        self.checkedAt = checkedAt; self.expiresAt = expiresAt; self.ticket = ticket
        self.managedSessions = managedSessions
        self.sessions = sessions
    }
}

/// Deliberately excludes executable paths, arguments, environment and working directories.
public struct GuardSessionSummary: Codable, Sendable, Identifiable {
    public var id: String { "\(pid):\(startSeconds):\(startMicroseconds)" }
    public let pid: pid_t
    public let startSeconds: UInt64
    public let startMicroseconds: UInt64
    public let isTopLevel: Bool
    public let decision: String
    public let safetyScore: Int?
    public let checkedAt: Date?
    public init(pid: pid_t, startSeconds: UInt64, startMicroseconds: UInt64,
                isTopLevel: Bool, decision: String, safetyScore: Int?, checkedAt: Date?) {
        self.pid = pid; self.startSeconds = startSeconds; self.startMicroseconds = startMicroseconds
        self.isTopLevel = isTopLevel; self.decision = decision; self.safetyScore = safetyScore
        self.checkedAt = checkedAt
    }
}

public enum GuardIPCError: Error { case invalidPath, system(Int32), invalidMessage, peer, unavailable }

/// Local, bounded, same-user IPC. Messages never contain command arguments.
public enum GuardIPC {
    public static var directory: String {
        NSHomeDirectory() + "/Library/Application Support/SafeClaude"
    }
    public static var socketPath: String { directory + "/agent.sock" }
    private static let maximumBytes = 32768

    public static func prepareDirectory(_ path: String = directory) throws {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try validateDirectory(path)
    }
    private static func validateDirectory(_ path: String) throws {
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == getuid(), (info.st_mode & 0o077) == 0 else { throw GuardIPCError.invalidPath }
    }
    private static func address(_ path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString)
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw GuardIPCError.invalidPath }
        withUnsafeMutableBytes(of: &address.sun_path) { dest in
            dest.copyBytes(from: bytes.map { UInt8(bitPattern: $0) } + Array(repeating: 0, count: dest.count - bytes.count))
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return address
    }
    private static func setTimeout(_ fd: Int32, seconds: Int, microseconds: Int = 0) {
        var timeout = timeval(tv_sec: seconds, tv_usec: Int32(microseconds))
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
        var enabled: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled)))
    }
    public static func connect(path: String = socketPath) throws -> Int32 {
        try validateDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFSOCK,
              info.st_uid == getuid(), (info.st_mode & 0o077) == 0 else { throw GuardIPCError.unavailable }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw GuardIPCError.system(errno) }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        do {
            var addr = try address(path)
            let result = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }}
            guard result == 0 else { throw GuardIPCError.unavailable }
            try verifyPeer(fd)
            setTimeout(fd, seconds: 2, microseconds: 500_000)
            return fd
        } catch { close(fd); throw error }
    }
    public static func listen(path: String = socketPath) throws -> Int32 {
        try prepareDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        // Keep the advisory lock open for the lifetime of the server, so two
        // starting agents cannot unlink each other's socket.
        let lock = open(path + ".lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lock >= 0 else { throw GuardIPCError.system(errno) }
        var keepLock = false
        defer { if !keepLock { close(lock) } }
        var lockInfo = stat()
        guard fstat(lock, &lockInfo) == 0, (lockInfo.st_mode & S_IFMT) == S_IFREG,
              lockInfo.st_uid == getuid(), (lockInfo.st_mode & 0o077) == 0,
              flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw GuardIPCError.unavailable }
        var info = stat()
        if lstat(path, &info) == 0 {
            guard (info.st_mode & S_IFMT) == S_IFSOCK, info.st_uid == getuid() else { throw GuardIPCError.invalidPath }
            if let existing = try? connect(path: path) { close(existing); throw GuardIPCError.unavailable }
            guard unlink(path) == 0 else { throw GuardIPCError.system(errno) }
        } else if errno != ENOENT { throw GuardIPCError.system(errno) }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw GuardIPCError.system(errno) }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        do {
            var addr = try address(path)
            let result = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }}
            guard result == 0 else { throw GuardIPCError.system(errno) }
            guard chmod(path, 0o600) == 0, Darwin.listen(fd, 32) == 0 else { throw GuardIPCError.system(errno) }
            keepLock = true
            return fd
        } catch { close(fd); throw error }
    }
    public static func verifyPeer(_ fd: Int32) throws {
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { throw GuardIPCError.peer }
    }
    public static func configureClient(_ fd: Int32) throws {
        try verifyPeer(fd); setTimeout(fd, seconds: 5)
    }
    public static func peerPID(_ fd: Int32) throws -> pid_t {
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0, pid > 1 else {
            throw GuardIPCError.peer
        }
        return pid
    }
    public static func send<T: Encodable>(_ value: T, fd: Int32) throws {
        let data = try JSONEncoder().encode(value)
        guard !data.isEmpty, data.count <= maximumBytes else { throw GuardIPCError.invalidMessage }
        var frame = Data()
        var length = UInt32(data.count).bigEndian
        withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
        frame.append(data)
        try frame.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw GuardIPCError.system(errno) }
                offset += n
            }
        }
    }
    public static func receive<T: Decodable>(_ type: T.Type, fd: Int32) throws -> T {
        func readExactly(_ count: Int) throws -> Data {
            var data = Data(count: count)
            try data.withUnsafeMutableBytes { bytes in
                var offset = 0
                while offset < count {
                    let n = Darwin.read(fd, bytes.baseAddress!.advanced(by: offset), count - offset)
                    if n < 0 && errno == EINTR { continue }
                    guard n > 0 else { throw GuardIPCError.invalidMessage }
                    offset += n
                }
            }
            return data
        }
        let header = try readExactly(4)
        let count = header.reduce(0) { ($0 << 8) | Int($1) }
        guard count > 0, count <= maximumBytes else { throw GuardIPCError.invalidMessage }
        return try JSONDecoder().decode(type, from: readExactly(count))
    }
}
