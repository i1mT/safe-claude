import CryptoKit
import Foundation

/// A privacy-minimized Claude Code StopFailure hook event.
/// The hook's error text and the rest of its stdin payload are never retained.
public struct ClaudeFailureEvent: Sendable, Equatable {
    public enum Kind: String, Sendable {
        case apiFailure
        case authenticationFailure
    }

    public let sessionDigest: String
    public let kind: Kind

    public static func parse(_ data: Data) -> ClaudeFailureEvent? {
        guard data.count <= 65_536,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["hook_event_name"] as? String == "StopFailure",
              let sessionID = object["session_id"] as? String,
              (1...512).contains(sessionID.utf8.count),
              !sessionID.utf8.contains(0),
              let errorType = object["error"] as? String,
              errorTypes.contains(errorType) else { return nil }

        let kind: Kind = authenticationErrorTypes.contains(errorType)
            ? .authenticationFailure : .apiFailure
        let digest = SHA256.hash(data: Data(sessionID.utf8))
            .map { String(format: "%02x", $0) }.joined()
        return ClaudeFailureEvent(sessionDigest: digest, kind: kind)
    }

    private static let errorTypes: Set<String> = [
        "rate_limit", "overloaded", "authentication_failed", "oauth_org_not_allowed",
        "account_on_hold", "billing_error", "invalid_request", "model_not_found",
        "server_error", "max_output_tokens", "cloud_credential_error", "unknown",
    ]

    private static let authenticationErrorTypes: Set<String> = [
        "authentication_failed", "oauth_org_not_allowed", "account_on_hold",
        "billing_error", "cloud_credential_error", "server_error", "unknown",
    ]

    private init(sessionDigest: String, kind: Kind) {
        self.sessionDigest = sessionDigest
        self.kind = kind
    }
}

public struct ClaudeFailureCounts: Sendable, Equatable {
    public let apiFailuresInMinute: Int
    public let authenticationFailuresInTenMinutes: Int
}

public enum ClaudeFailureDisposition {
    /// Missing score or policy is never evidence that a session is safe.
    public static func shouldTerminate(safetyScore: Int?, minimumScore: Int?) -> Bool {
        guard let safetyScore, (0...100).contains(safetyScore),
              let minimumScore, (0...100).contains(minimumScore) else { return true }
        return safetyScore < minimumScore
    }
}

/// Bounded rolling metadata for opaque Claude Code session identifiers.
/// Only event timestamps, an event class, and a SHA-256 session digest persist.
public actor ClaudeFailureTracker {
    private struct Entry: Codable {
        let sessionDigest: String
        var apiFailures: [Date]
        var authenticationFailures: [Date]
    }
    private struct FileData: Codable {
        let version: Int
        var entries: [Entry]
    }

    private let path: String
    private var entries: [String: Entry] = [:]
    private var loaded = false
    private var failed = false

    public init(path: String) { self.path = path }

    public func record(_ event: ClaudeFailureEvent, at now: Date = Date()) throws -> ClaudeFailureCounts {
        try record(sessionDigest: event.sessionDigest, kind: event.kind, at: now)
    }

    public func record(sessionDigest: String, kind: ClaudeFailureEvent.Kind,
                       at now: Date = Date()) throws -> ClaudeFailureCounts {
        try loadIfNeeded(now: now)
        guard !failed, now.timeIntervalSince1970.isFinite, Self.validDigest(sessionDigest) else {
            throw GuardIPCError.invalidMessage
        }
        let previous = entries[sessionDigest]
        var entry = entries[sessionDigest] ?? Entry(
            sessionDigest: sessionDigest, apiFailures: [], authenticationFailures: [])
        entry.apiFailures.removeAll { !(0...60).contains(now.timeIntervalSince($0)) }
        entry.authenticationFailures.removeAll { !(0...600).contains(now.timeIntervalSince($0)) }
        entry.apiFailures.append(now)
        if kind == .authenticationFailure { entry.authenticationFailures.append(now) }
        if entry.apiFailures.count > 128 { entry.apiFailures.removeFirst(entry.apiFailures.count - 128) }
        if entry.authenticationFailures.count > 128 {
            entry.authenticationFailures.removeFirst(entry.authenticationFailures.count - 128)
        }
        entries[sessionDigest] = entry
        if entries.count > 512,
           let oldest = entries.min(by: {
               max($0.value.apiFailures.last ?? .distantPast,
                   $0.value.authenticationFailures.last ?? .distantPast) <
               max($1.value.apiFailures.last ?? .distantPast,
                   $1.value.authenticationFailures.last ?? .distantPast)
           })?.key {
            entries.removeValue(forKey: oldest)
        }
        do { try persist() }
        catch {
            if let previous { entries[sessionDigest] = previous }
            else { entries.removeValue(forKey: sessionDigest) }
            throw error
        }
        return try counts(for: sessionDigest, at: now)
    }

    public func counts(for digest: String, at now: Date = Date()) throws -> ClaudeFailureCounts {
        try loadIfNeeded(now: now)
        guard !failed, Self.validDigest(digest) else { throw GuardIPCError.invalidMessage }
        let entry = entries[digest]
        return ClaudeFailureCounts(
            apiFailuresInMinute: entry?.apiFailures.filter {
                (0...60).contains(now.timeIntervalSince($0))
            }.count ?? 0,
            authenticationFailuresInTenMinutes: entry?.authenticationFailures.filter {
                (0...600).contains(now.timeIntervalSince($0))
            }.count ?? 0)
    }

    private func loadIfNeeded(now: Date) throws {
        guard !loaded else { return }
        loaded = true
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT { return }
            failed = true
            throw GuardIPCError.system(errno)
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), (info.st_mode & 0o077) == 0,
              info.st_size <= 262_144 else {
            failed = true
            throw GuardIPCError.invalidPath
        }
        do {
            let data = try BoundedFile.read(fd, maximum: 262_144)
            let decoded = try JSONDecoder().decode(FileData.self, from: data)
            guard decoded.version == 1, decoded.entries.count <= 512,
                  decoded.entries.allSatisfy({ entry in
                      Self.validDigest(entry.sessionDigest) &&
                      entry.apiFailures.count <= 128 && entry.authenticationFailures.count <= 128 &&
                      entry.apiFailures.allSatisfy { $0 <= now.addingTimeInterval(5) } &&
                      entry.authenticationFailures.allSatisfy { $0 <= now.addingTimeInterval(5) }
                  }),
                  Set(decoded.entries.map(\.sessionDigest)).count == decoded.entries.count else {
                throw GuardIPCError.invalidMessage
            }
            entries = Dictionary(uniqueKeysWithValues: decoded.entries.map { value in
                var entry = value
                entry.apiFailures.removeAll { !(0...60).contains(now.timeIntervalSince($0)) }
                entry.authenticationFailures.removeAll { !(0...600).contains(now.timeIntervalSince($0)) }
                return (entry.sessionDigest, entry)
            })
        } catch {
            failed = true
            throw error
        }
    }

    private func persist() throws {
        try GuardIPC.prepareDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        let data = try JSONEncoder().encode(FileData(version: 1, entries: Array(entries.values)))
        guard data.count <= 262_144 else { throw GuardIPCError.invalidMessage }
        let temporary = path + "." + UUID().uuidString + ".tmp"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(fd); unlink(temporary) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { throw GuardIPCError.system(errno) }
                offset += written
            }
        }
        guard fsync(fd) == 0, rename(temporary, path) == 0 else { throw GuardIPCError.system(errno) }
    }

    private static func validDigest(_ value: String) -> Bool {
        value.utf8.count == 64 &&
            value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}
