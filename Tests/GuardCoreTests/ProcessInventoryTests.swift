import Foundation
import XCTest
@testable import GuardCore

final class ProcessInventoryTests: XCTestCase {
    func testDetectsOnlyUnregisteredMatchingExecutable() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent("inventory-fixture")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/sleep"), to: executable)
        let child = Process()
        child.executableURL = executable
        child.arguments = ["20"]
        try child.run()
        defer { if child.isRunning { child.terminate() }; child.waitUntilExit() }
        let identity = try XCTUnwrap(ProcessIdentity.read(child.processIdentifier))
        XCTAssertEqual(ProcessInventory.hasUnmanaged(executable: executable.path, managed: []), true)
        let record = SessionRecord(identity: identity, executable: executable.path, isTopLevel: true)
        XCTAssertEqual(ProcessInventory.hasUnmanaged(executable: executable.path, managed: [record]), false)
    }

    func testDetectsOtherRunningClaudeInstallationWithoutReturningItsPath() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let other = root.appendingPathComponent("claude")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/sleep"), to: other)
        let child = Process()
        child.executableURL = other
        child.arguments = ["20"]
        try child.run()
        defer { if child.isRunning { child.terminate() }; child.waitUntilExit() }
        XCTAssertEqual(ProcessInventory.hasOtherClaudeInstallation(excluding: "/usr/bin/claude"), true)
    }

    func testClaudeInstallationClassificationRequiresCompleteNegativeScan() {
        XCTAssertEqual(ProcessInventory.classifyClaudeInstallations(
            excluding: "/opt/safe/claude", candidatePaths: ["/opt/safe/claude", "/bin/zsh"],
            complete: true), false)
        XCTAssertEqual(ProcessInventory.classifyClaudeInstallations(
            excluding: "/opt/safe/claude", candidatePaths: ["/opt/other/claude"], complete: false), true)
        XCTAssertNil(ProcessInventory.classifyClaudeInstallations(
            excluding: "/opt/safe/claude", candidatePaths: ["/bin/zsh"], complete: false))
    }
}
