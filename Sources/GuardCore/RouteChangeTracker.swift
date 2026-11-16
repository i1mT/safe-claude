import CryptoKit
import Darwin
import Foundation

/// Counts observed proxy and active DNS route transitions in a rolling
/// ten-minute window. Missing or interrupted samples never establish a pass.
public actor RouteChangeTracker {
    private struct StoredState: Codable {
        let version: Int
        let keyID: Data?
        let previousDigest: Data?
        let changes: [TimeInterval]
        let coverageStartedAt: TimeInterval?
        let lastObservedAt: TimeInterval?
    }

    private static let window: TimeInterval = 600
    /// Agent sampling runs every two seconds. A gap this large breaks the
    /// observation window so sleep, stalls, or downtime cannot look like proof.
    private static let maximumGap: TimeInterval = 10
    private static let persistenceHeartbeat: TimeInterval = 15

    private let path: String?
    private let key: SymmetricKey?
    private let persistentKeyID: Data?
    private var previous: Data?
    private var changes: [TimeInterval] = []
    private var coverageStartedAt: TimeInterval?
    private var lastObservedAt: TimeInterval?
    private var lastPersistedAt: TimeInterval?
    private var persistenceHealthy = true

    public init() {
        path = nil
        key = nil
        persistentKeyID = nil
    }

    /// Persists only keyed route fingerprints and monotonic timestamps.
    /// Raw proxy and DNS configuration values are never written to disk.
    public init(persistentPath: String, keyData: Data) throws {
        guard persistentPath.hasPrefix("/"), keyData.count == 32,
              !persistentPath.utf8.contains(0) else {
            throw GuardIPCError.invalidMessage
        }
        path = persistentPath
        key = SymmetricKey(data: keyData)
        persistentKeyID = Self.keyIdentifier(keyData)
        let parent = URL(fileURLWithPath: persistentPath).deletingLastPathComponent().path
        try GuardIPC.prepareDirectory(parent)

        let fd = open(persistentPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            guard errno == ENOENT else { throw GuardIPCError.system(errno) }
            return
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), (info.st_mode & 0o077) == 0,
              (0...65_536).contains(info.st_size) else {
            throw GuardIPCError.invalidPath
        }
        let data = try BoundedFile.read(fd, maximum: 65_536)
        let stored = try JSONDecoder().decode(StoredState.self, from: data)
        guard stored.version == 1,
              stored.keyID == nil || stored.keyID?.count == 32,
              stored.previousDigest == nil || stored.previousDigest?.count == 32,
              stored.changes.count <= 1_024,
              stored.changes.allSatisfy({ $0.isFinite && $0 >= 0 }),
              stored.coverageStartedAt.map({ $0.isFinite && $0 >= 0 }) ?? true,
              stored.lastObservedAt.map({ $0.isFinite && $0 >= 0 }) ?? true else {
            throw GuardIPCError.invalidMessage
        }

        let uptime = ProcessInfo.processInfo.systemUptime
        guard stored.keyID == persistentKeyID else {
            lastPersistedAt = uptime - Self.persistenceHeartbeat
            return
        }
        previous = stored.previousDigest
        changes = stored.changes.filter { $0 <= uptime && uptime - $0 <= Self.window }
        var restoredCoverageStartedAt: TimeInterval?
        var restoredLastObservedAt: TimeInterval?
        if let started = stored.coverageStartedAt,
           let last = stored.lastObservedAt,
           last <= uptime, uptime - last <= Self.maximumGap {
            if started <= last {
                restoredCoverageStartedAt = started
                restoredLastObservedAt = last
            }
        }
        coverageStartedAt = restoredCoverageStartedAt
        lastObservedAt = restoredLastObservedAt
        let coverageWasReset = stored.coverageStartedAt != nil && restoredCoverageStartedAt == nil
        let changesWerePruned = changes.count != stored.changes.count
        lastPersistedAt = changesWerePruned || coverageWasReset
            ? uptime - Self.persistenceHeartbeat : uptime
    }

    public func observe(_ fingerprint: Data?,
                        at uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        guard uptime.isFinite, uptime >= 0 else { return }
        prune(at: uptime)

        guard let fingerprint, let digest = stableDigest(fingerprint) else {
            let changed = previous != nil || coverageStartedAt != nil || lastObservedAt != nil
            previous = nil
            coverageStartedAt = nil
            lastObservedAt = nil
            if changed { persistOrFail(at: uptime) }
            return
        }

        if let lastObservedAt, uptime < lastObservedAt ||
            uptime - lastObservedAt > Self.maximumGap {
            coverageStartedAt = nil
        }
        if previous == nil || coverageStartedAt == nil {
            coverageStartedAt = uptime
        }
        if let previous, previous != digest {
            changes.append(uptime)
            if changes.count > 1_024 {
                changes.removeFirst(changes.count - 1_024)
            }
        }
        let fingerprintChanged = previous != digest
        previous = digest
        lastObservedAt = uptime

        if fingerprintChanged ||
            lastPersistedAt.map({ uptime < $0 || uptime - $0 >= Self.persistenceHeartbeat }) ?? true {
            persistOrFail(at: uptime)
        }
    }

    public func resetContinuity() {
        coverageStartedAt = nil
        lastObservedAt = nil
        persistOrFail(at: ProcessInfo.processInfo.systemUptime)
    }

    public func count(at uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Int? {
        guard persistenceHealthy, uptime.isFinite, uptime >= 0 else { return nil }
        return changes.filter { $0 <= uptime && uptime - $0 <= Self.window }.count
    }

    public func windowCovered(at uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        guard persistenceHealthy, uptime.isFinite, uptime >= 0,
              let started = coverageStartedAt, let last = lastObservedAt,
              last <= uptime, uptime - last <= 5,
              uptime >= started else { return false }
        return uptime - started >= Self.window
    }

    private func stableDigest(_ fingerprint: Data) -> Data? {
        guard !fingerprint.isEmpty, fingerprint.count <= 65_536 else { return nil }
        if path != nil, fingerprint.count != 32 { return nil }
        guard let key else { return fingerprint }
        return Data(HMAC<SHA256>.authenticationCode(for: fingerprint, using: key))
    }

    private static func keyIdentifier(_ keyData: Data) -> Data {
        let key = SymmetricKey(data: keyData)
        let label = Data("safeclaude.route-change-state.v1".utf8)
        return Data(HMAC<SHA256>.authenticationCode(for: label, using: key))
    }

    private func prune(at uptime: TimeInterval) {
        changes.removeAll { $0 > uptime || uptime - $0 > Self.window }
    }

    private func persistOrFail(at uptime: TimeInterval) {
        do {
            try persist()
            lastPersistedAt = uptime
        } catch {
            persistenceHealthy = false
        }
    }

    private func persist() throws {
        guard let path else { return }
        let state = StoredState(version: 1, keyID: persistentKeyID,
                                previousDigest: previous, changes: changes,
                                coverageStartedAt: coverageStartedAt,
                                lastObservedAt: lastObservedAt)
        let data = try JSONEncoder().encode(state)
        guard data.count <= 65_536 else { throw GuardIPCError.invalidMessage }
        let temporary = path + "." + UUID().uuidString + ".tmp"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(fd); unlink(temporary) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw GuardIPCError.system(errno) }
                offset += count
            }
        }
        guard fsync(fd) == 0, rename(temporary, path) == 0 else {
            throw GuardIPCError.system(errno)
        }
    }
}
