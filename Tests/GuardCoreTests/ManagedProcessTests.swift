import Darwin
import Foundation
import XCTest
@testable import GuardCore

final class ManagedProcessTests: XCTestCase {
    func testFindsRegisteredAncestorAndStopsOnlyThatProcess() async throws {
        let parent = Process()
        parent.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        parent.arguments = ["-c", """
import subprocess
p = subprocess.Popen(['/bin/sleep', '30'])
print(p.pid, flush=True)
p.wait()
"""]
        let output = Pipe()
        parent.standardOutput = output
        parent.standardError = FileHandle.nullDevice
        try parent.run()
        defer { if parent.isRunning { parent.terminate() }; parent.waitUntilExit() }
        let line = try XCTUnwrap(String(data: output.fileHandleForReading.availableData, encoding: .utf8))
        let childPID = try XCTUnwrap(pid_t(line.trimmingCharacters(in: .whitespacesAndNewlines)))
        defer { if let child = ProcessIdentity.read(childPID) { _ = child.signal(SIGTERM) } }
        let parentIdentity = try XCTUnwrap(ProcessIdentity.read(parent.processIdentifier))
        let childIdentity = try XCTUnwrap(ProcessIdentity.read(childPID))
        let stale = ProcessIdentity(pid: parentIdentity.pid, uid: parentIdentity.uid,
            startSeconds: parentIdentity.startSeconds + 1, startMicroseconds: parentIdentity.startMicroseconds,
            executable: parentIdentity.executable)
        XCTAssertNil(ManagedProcess.ancestor(of: childIdentity,
            records: [SessionRecord(identity: stale, executable: stale.executable)]))
        let record = SessionRecord(identity: parentIdentity, executable: parentIdentity.executable)
        let ancestor = try XCTUnwrap(ManagedProcess.ancestor(of: childIdentity, records: [record]))
        XCTAssertEqual(ancestor, parentIdentity)
        let stopped = await ManagedProcess.terminate(ancestor, force: true, gracefulDelay: 0.3, killDelay: 0.3)
        XCTAssertTrue(stopped)
        XCTAssertFalse(parent.isRunning)
        XCTAssertTrue(childIdentity.stillMatches())
    }
}
