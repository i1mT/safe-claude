import Darwin
import Foundation

/// Tracks only fixed authentication method labels. Credential values never
/// enter this type, its state file, or an IPC message.
public enum AuthenticationContext {
    public static let modes: Set<String> = [
        "api-key", "auth-token", "bedrock", "vertex", "api-key-helper", "claude-managed",
    ]

    public static func processMode() -> String? {
        var detected = Set<String>()
        if getenv("ANTHROPIC_API_KEY") != nil { detected.insert("api-key") }
        if getenv("ANTHROPIC_AUTH_TOKEN") != nil { detected.insert("auth-token") }
        if truthy(getenv("CLAUDE_CODE_USE_BEDROCK")) { detected.insert("bedrock") }
        if truthy(getenv("CLAUDE_CODE_USE_VERTEX")) { detected.insert("vertex") }
        return detected.isEmpty ? nil : encode(detected)
    }

    public static func combine(processMode: String?, settingsModes: Set<String>) -> String? {
        var combined = settingsModes
        if let processMode {
            guard isValid(processMode) else { return nil }
            combined.formUnion(processMode.split(separator: "+").map(String.init))
        }
        guard combined.isSubset(of: modes) else { return nil }
        return encode(combined.isEmpty ? ["claude-managed"] : combined)
    }

    public static func isValid(_ value: String) -> Bool {
        guard value.utf8.count <= 128 else { return false }
        let items = value.split(separator: "+").map(String.init)
        return !items.isEmpty && items.count <= modes.count &&
            Set(items).count == items.count && Set(items).isSubset(of: modes) &&
            encode(Set(items)) == value
    }

    private static func encode(_ values: Set<String>) -> String {
        values.sorted().joined(separator: "+")
    }

    private static func truthy(_ raw: UnsafeMutablePointer<CChar>?) -> Bool {
        guard let raw else { return false }
        return ["1", "true", "yes", "on"].contains(String(cString: raw).lowercased())
    }
}

public actor AuthenticationContextTracker {
    private struct State: Codable {
        var current: String
        var currentObservedAt: Date
        var transitions: [Date]
    }

    private let path: String
    private var state: State?
    private var loadFailed = false

    public init(path: String) {
        self.path = path
    }

    public func observe(_ context: String?, at now: Date = Date()) -> ObservationStatus {
        guard let context, AuthenticationContext.isValid(context) else {
            return .unknown(source: "auth-context", critical: true)
        }
        if state == nil && !loadFailed {
            do { state = try load() }
            catch { loadFailed = true }
        }
        guard !loadFailed else { return .unknown(source: "auth-context", critical: true) }

        var next = state
        if var existing = next, now.timeIntervalSince(existing.currentObservedAt) > 600 {
            existing.current = context
            existing.currentObservedAt = now
            existing.transitions = []
            next = existing
        } else if var existing = next {
            if existing.current != context { existing.transitions.append(now) }
            existing.current = context
            existing.currentObservedAt = now
            existing.transitions.removeAll { now.timeIntervalSince($0) > 600 || $0 > now }
            if existing.transitions.count > 64 {
                existing.transitions.removeFirst(existing.transitions.count - 64)
            }
            next = existing
        } else {
            next = State(current: context, currentObservedAt: now, transitions: [])
        }
        guard let next else { return .unknown(source: "auth-context", critical: true) }
        do { try save(next) }
        catch { return .unknown(source: "auth-context", critical: true) }
        state = next
        return next.transitions.count >= 3
            ? .triggered(.standard, deduplicationKey: nil) : .passed
    }

    private func load() throws -> State? {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw GuardIPCError.system(errno)
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), (info.st_mode & 0o077) == 0,
              info.st_size <= 16_384 else { throw GuardIPCError.invalidPath }
        let data = try BoundedFile.read(fd, maximum: 16_384)
        let decoded = try JSONDecoder().decode(State.self, from: data)
        let now = Date()
        guard AuthenticationContext.isValid(decoded.current),
              decoded.transitions.count <= 64,
              decoded.transitions.allSatisfy({ now.timeIntervalSince($0) >= 0 && now.timeIntervalSince($0) <= 600 }),
              decoded.transitions == decoded.transitions.sorted(),
              decoded.currentObservedAt <= now.addingTimeInterval(5) else {
            throw GuardIPCError.invalidMessage
        }
        return decoded
    }

    private func save(_ value: State) throws {
        try GuardIPC.prepareDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        let data = try JSONEncoder().encode(value)
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
        let directory = URL(fileURLWithPath: path).deletingLastPathComponent().path
        let directoryFD = open(directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW)
        guard directoryFD >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(directoryFD) }
        guard fsync(directoryFD) == 0 else { throw GuardIPCError.system(errno) }
    }
}
