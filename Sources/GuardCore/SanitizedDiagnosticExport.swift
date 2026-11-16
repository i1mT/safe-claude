import Darwin
import Foundation

/// Writes a user-requested diagnostic without exposing a partially written or
/// broadly readable report.
public enum SanitizedDiagnosticExport {
    public static func write(_ report: SanitizedDiagnosticReport, to destination: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(report)

        let directory = destination.deletingLastPathComponent().resolvingSymlinksInPath()
        let destinationName = destination.lastPathComponent
        guard !destinationName.isEmpty, destinationName != ".", destinationName != ".." else {
            throw GuardIPCError.invalidPath
        }
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(directoryFD) }

        let temporaryName = ".safeclaude-diagnostic-\(UUID().uuidString).tmp"
        let temporaryFD = temporaryName.withCString {
            openat(directoryFD, $0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        }
        guard temporaryFD >= 0 else { throw GuardIPCError.system(errno) }
        var renamed = false
        defer {
            close(temporaryFD)
            if !renamed {
                temporaryName.withCString { _ = unlinkat(directoryFD, $0, 0) }
            }
        }

        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(temporaryFD,
                                         bytes.baseAddress!.advanced(by: offset),
                                         bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw GuardIPCError.system(errno) }
                offset += count
            }
        }
        guard fsync(temporaryFD) == 0 else { throw GuardIPCError.system(errno) }
        let renameResult = temporaryName.withCString { temporaryCString in
            destinationName.withCString { destinationCString in
                renameat(directoryFD, temporaryCString, directoryFD, destinationCString)
            }
        }
        guard renameResult == 0 else {
            throw GuardIPCError.system(errno)
        }
        renamed = true
        guard fsync(directoryFD) == 0 else { throw GuardIPCError.system(errno) }
    }
}
