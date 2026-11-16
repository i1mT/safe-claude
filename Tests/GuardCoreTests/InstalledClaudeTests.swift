import Foundation
import Darwin
import XCTest
@testable import GuardCore

final class InstalledClaudeTests: XCTestCase {
    func testExecutableIdentityDetectsReplacementOrMutation() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("claude")
        let metadata = root.appendingPathComponent("identity.json")
        try Data("fixture".utf8).write(to: target)
        var info = stat()
        XCTAssertEqual(stat(target.path, &info), 0)
        let identity: [String: Any] = ["device": Int64(info.st_dev), "inode": UInt64(info.st_ino),
            "size": info.st_size, "modifiedSeconds": info.st_mtimespec.tv_sec,
            "modifiedNanoseconds": info.st_mtimespec.tv_nsec]
        try JSONSerialization.data(withJSONObject: identity).write(to: metadata)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: metadata.path)
        XCTAssertEqual(InstalledClaude.identityMatches(executable: target.path, identityFile: metadata.path), true)
        try Data("changed fixture".utf8).write(to: target)
        XCTAssertEqual(InstalledClaude.identityMatches(executable: target.path, identityFile: metadata.path), false)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: metadata.path)
        XCTAssertNil(InstalledClaude.identityMatches(executable: target.path, identityFile: metadata.path))
    }
    func testOnlyProtectedValidTargetFileIsAccepted() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("target")
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/bin/sleep")
        try Data((link.path + "\n").utf8).write(to: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        XCTAssertEqual(InstalledClaude.matches(requestedExecutable: "/bin/sleep", targetFile: target.path), true)
        XCTAssertEqual(InstalledClaude.matches(requestedExecutable: "/bin/echo", targetFile: target.path), false)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: target.path)
        XCTAssertNil(InstalledClaude.matches(requestedExecutable: "/bin/sleep", targetFile: target.path))
        try FileManager.default.removeItem(at: target)
        try FileManager.default.createSymbolicLink(atPath: target.path, withDestinationPath: link.path)
        XCTAssertNil(InstalledClaude.matches(requestedExecutable: "/bin/sleep", targetFile: target.path))
    }
}
