import Darwin
import Foundation

/// Persists only recent authorized top-level launch timestamps. The file
/// contains no PID, executable path, account data, arguments, or session ID.
public actor LaunchRateTracker {
    private struct Store: Codable {
        let version: Int
        let starts: [Date]
    }

    private let path: String
    private var starts: [Date]
    private let window: TimeInterval
    private let now: @Sendable () -> Date

    public init(path: String, window: TimeInterval = 60,
                now: @escaping @Sendable () -> Date = Date.init) throws {
        guard path.hasPrefix("/"), !path.utf8.contains(0), window > 0 else {
            throw GuardIPCError.invalidPath
        }
        self.path = path
        self.window = window
        self.now = now
        try GuardIPC.prepareDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)

        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            guard errno == ENOENT else { throw GuardIPCError.system(errno) }
            starts = []
            return
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), (info.st_mode & 0o077) == 0,
              (0...16_384).contains(info.st_size) else {
            throw GuardIPCError.invalidPath
        }
        let data = try BoundedFile.read(fd, maximum: 16_384)
        let store = try JSONDecoder().decode(Store.self, from: data)
        let current = now()
        guard store.version == 1, store.starts.count <= 256,
              store.starts.allSatisfy({ $0 <= current && current.timeIntervalSince($0) <= 86_400 }) else {
            throw GuardIPCError.invalidMessage
        }
        starts = store.starts.filter { (0...window).contains(current.timeIntervalSince($0)) }
    }

    public func count() -> Int? {
        let current = now()
        guard starts.allSatisfy({ $0 <= current }) else { return nil }
        starts.removeAll { current.timeIntervalSince($0) > window }
        return starts.count
    }

    @discardableResult
    public func recordStart() throws -> Int {
        let current = now()
        starts.removeAll { !(0...window).contains(current.timeIntervalSince($0)) }
        guard starts.count < 256 else { throw GuardIPCError.invalidMessage }
        let previous = starts
        starts.append(current)
        do {
            try persist()
        } catch {
            starts = previous
            throw error
        }
        return starts.count
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(Store(version: 1, starts: starts))
        guard data.count <= 16_384 else { throw GuardIPCError.invalidMessage }
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
        guard fsync(fd) == 0, rename(temporary, path) == 0 else {
            throw GuardIPCError.system(errno)
        }
        let parent = open(URL(fileURLWithPath: path).deletingLastPathComponent().path,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        if parent >= 0 {
            defer { close(parent) }
            guard fsync(parent) == 0 else { throw GuardIPCError.system(errno) }
        }
    }
}
