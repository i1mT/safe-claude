import Darwin
import Foundation

public enum NetworkTimeStatusValue: String, Codable, Sendable {
    case enabled
    case disabled
    case unavailable
}

public struct NetworkTimeStatusSnapshot: Codable, Sendable, Equatable {
    public let version: Int
    public let value: NetworkTimeStatusValue
    public let observedAt: Date

    public init(value: NetworkTimeStatusValue, observedAt: Date = Date()) {
        version = 1
        self.value = value
        self.observedAt = observedAt
    }
}

public enum NetworkTimeStatus {
    public static let path = "/Library/Application Support/SafeClaude/network-time-status.json"
    public static let maximumAge: TimeInterval = 180

    public static func parseSystemSetup(output: String, exitCode: Int32) -> NetworkTimeStatusValue? {
        guard exitCode == 0, output.utf8.count <= 4096 else { return nil }
        let lines = output.split(whereSeparator: \.isNewline).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard lines.count == 1, let line = lines.first else { return nil }
        switch line {
        case "Network Time: On": return .enabled
        case "Network Time: Off": return .disabled
        default: return nil
        }
    }

    public static func validatedSnapshot(from data: Data, now: Date = Date())
        -> NetworkTimeStatusSnapshot? {
        guard data.count <= 4096,
              let snapshot = try? JSONDecoder().decode(NetworkTimeStatusSnapshot.self, from: data),
              snapshot.version == 1,
              snapshot.observedAt.timeIntervalSince1970.isFinite,
              isFresh(snapshot, now: now) else { return nil }
        return snapshot
    }

    public static func isFresh(_ snapshot: NetworkTimeStatusSnapshot, now: Date = Date()) -> Bool {
        let age = now.timeIntervalSince(snapshot.observedAt)
        return age.isFinite && (-5...maximumAge).contains(age)
    }

    public static func read(path: String = Self.path,
                            now: Date = Date()) -> NetworkTimeStatusSnapshot? {
        guard path == Self.path else { return nil }
        let directory = URL(fileURLWithPath: path).deletingLastPathComponent().path
        guard secureRootDirectory(directory) else { return nil }
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              isTrustedStatusFile(owner: info.st_uid, mode: info.st_mode, size: info.st_size) else {
            return nil
        }
        guard let bytes = try? BoundedFile.read(fd, maximum: 4096) else { return nil }
        return validatedSnapshot(from: bytes, now: now)
    }

    static func isTrustedStatusFile(owner: uid_t, mode: mode_t, size: off_t) -> Bool {
        (mode & S_IFMT) == S_IFREG &&
            owner == 0 &&
            (mode & 0o022) == 0 &&
            size > 0 &&
            size <= 4096
    }

    static func isTrustedRootDirectory(owner: uid_t, mode: mode_t) -> Bool {
        isTrustedDirectory(owner: owner, mode: mode, expectedOwner: 0)
    }

    static func isTrustedDirectory(owner: uid_t, mode: mode_t, expectedOwner: uid_t) -> Bool {
        (mode & S_IFMT) == S_IFDIR && owner == expectedOwner && (mode & 0o022) == 0
    }

    public static func write(_ snapshot: NetworkTimeStatusSnapshot,
                             path: String = Self.path) throws {
        guard path == Self.path, geteuid() == 0,
              snapshot.version == 1,
              snapshot.observedAt.timeIntervalSince1970.isFinite,
              (-5...5).contains(Date().timeIntervalSince(snapshot.observedAt)) else {
            throw GuardIPCError.invalidPath
        }
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        guard secureRootDirectory(parent, createIfMissing: true) else {
            throw GuardIPCError.invalidPath
        }
        let data = try JSONEncoder().encode(snapshot)
        guard data.count <= 4096 else { throw GuardIPCError.invalidMessage }
        let temporary = path + ".\(UUID().uuidString).tmp"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard fd >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(fd); unlink(temporary) }
        guard fchown(fd, 0, 0) == 0, fchmod(fd, 0o644) == 0 else {
            throw GuardIPCError.system(errno)
        }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let amount = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if amount < 0 {
                    if errno == EINTR { continue }
                    throw GuardIPCError.system(errno)
                }
                guard amount > 0 else { throw GuardIPCError.invalidMessage }
                offset += amount
            }
        }
        guard fsync(fd) == 0, rename(temporary, path) == 0 else {
            throw GuardIPCError.system(errno)
        }
        let directoryFD = open(parent, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        guard directoryFD >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(directoryFD) }
        guard fsync(directoryFD) == 0 else { throw GuardIPCError.system(errno) }
    }

    public static func remove() throws -> Bool {
        guard geteuid() == 0 else { throw GuardIPCError.invalidPath }
        return try removeSnapshotFile(at: path, expectedOwner: 0)
    }

    static func removeSnapshotFile(at path: String, expectedOwner: uid_t) throws -> Bool {
        guard path.hasPrefix("/") else { throw GuardIPCError.invalidPath }
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        let directoryFD = open(parent, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        guard directoryFD >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(directoryFD) }

        var directoryInfo = stat()
        guard fstat(directoryFD, &directoryInfo) == 0,
              isTrustedDirectory(owner: directoryInfo.st_uid, mode: directoryInfo.st_mode,
                                 expectedOwner: expectedOwner) else {
            throw GuardIPCError.invalidPath
        }
        let filename = URL(fileURLWithPath: path).lastPathComponent
        var fileInfo = stat()
        if fstatat(directoryFD, filename, &fileInfo, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return true }
            throw GuardIPCError.system(errno)
        }
        guard isSafeToRemoveStatusFile(owner: fileInfo.st_uid, expectedOwner: expectedOwner,
                                       mode: fileInfo.st_mode,
                                       size: fileInfo.st_size, linkCount: fileInfo.st_nlink) else {
            throw GuardIPCError.invalidPath
        }
        guard unlinkat(directoryFD, filename, 0) == 0,
              fsync(directoryFD) == 0 else {
            throw GuardIPCError.system(errno)
        }
        return true
    }

    static func isSafeToRemoveStatusFile(owner: uid_t, expectedOwner: uid_t,
                                         mode: mode_t, size: off_t, linkCount: nlink_t) -> Bool {
        (mode & S_IFMT) == S_IFREG &&
            owner == expectedOwner &&
            (mode & 0o7777) == 0o644 &&
            size >= 0 &&
            size <= 4096 &&
            linkCount == 1
    }

    private static func secureRootDirectory(_ path: String, createIfMissing: Bool = false) -> Bool {
        var info = stat()
        if lstat(path, &info) != 0, errno == ENOENT, createIfMissing {
            guard mkdir(path, 0o755) == 0 || errno == EEXIST else { return false }
            guard chown(path, 0, 0) == 0, chmod(path, 0o755) == 0 else { return false }
            guard lstat(path, &info) == 0 else { return false }
        }
        guard isTrustedRootDirectory(owner: info.st_uid, mode: info.st_mode) else { return false }
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var opened = stat()
        return fstat(fd, &opened) == 0 && opened.st_dev == info.st_dev &&
            opened.st_ino == info.st_ino &&
            isTrustedRootDirectory(owner: opened.st_uid, mode: opened.st_mode)
    }
}
