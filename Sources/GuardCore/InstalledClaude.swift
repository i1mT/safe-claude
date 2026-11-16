import Darwin
import Foundation

/// Compares only the installation's selected executable path. This check
/// does not read Claude's configuration, arguments, or credentials.
public enum InstalledClaude {
    private struct FileIdentity: Decodable {
        let device: Int64
        let inode: UInt64
        let size: Int64
        let modifiedSeconds: Int64
        let modifiedNanoseconds: Int64
    }
    public static func matches(requestedExecutable: String, targetFile: String) -> Bool? {
        guard requestedExecutable.hasPrefix("/"), !requestedExecutable.utf8.contains(0) else { return nil }
        guard let resolved = selectedExecutable(targetFile: targetFile) else { return nil }
        let requested = URL(fileURLWithPath: requestedExecutable).resolvingSymlinksInPath().path
        return resolved == requested
    }
    public static func selectedExecutable(targetFile: String) -> String? {
        let fd = open(targetFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), (info.st_mode & 0o077) == 0,
              (1...4096).contains(info.st_size),
              let data = try? BoundedFile.read(fd, maximum: 4096),
              data.count == info.st_size, let text = String(data: data, encoding: .utf8),
              text.hasSuffix("\n"), text.filter({ $0 == "\n" }).count == 1 else { return nil }
        let target = String(text.dropLast())
        guard target.hasPrefix("/"), !target.utf8.contains(0),
              FileManager.default.isExecutableFile(atPath: target) else { return nil }
        return URL(fileURLWithPath: target).resolvingSymlinksInPath().path
    }
    public static func identityMatches(executable: String, identityFile: String) -> Bool? {
        guard executable.hasPrefix("/"), !executable.utf8.contains(0) else { return nil }
        let metadataFD = open(identityFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard metadataFD >= 0 else { return nil }
        defer { close(metadataFD) }
        var metadataStat = stat()
        guard fstat(metadataFD, &metadataStat) == 0, (metadataStat.st_mode & S_IFMT) == S_IFREG,
              metadataStat.st_uid == getuid(), (metadataStat.st_mode & 0o077) == 0,
              (1...4096).contains(metadataStat.st_size),
              let data = try? BoundedFile.read(metadataFD, maximum: 4096),
              data.count == metadataStat.st_size,
              let expected = try? JSONDecoder().decode(FileIdentity.self, from: data) else { return nil }
        let fd = open(executable, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var actual = stat()
        guard fstat(fd, &actual) == 0, (actual.st_mode & S_IFMT) == S_IFREG else { return nil }
        return expected.device == Int64(actual.st_dev) && expected.inode == UInt64(actual.st_ino) &&
            expected.size == actual.st_size && expected.modifiedSeconds == actual.st_mtimespec.tv_sec &&
            expected.modifiedNanoseconds == actual.st_mtimespec.tv_nsec
    }
}
