import Darwin
import Foundation
import XCTest
@testable import GuardCore

final class SessionJournalTests: XCTestCase {
    func testPersistenceContainsOnlyIdentityAndRejectsDuplicate() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("sessions.json").path
        let identity = try XCTUnwrap(ProcessIdentity.read(getpid()))
        let record = SessionRecord(identity: identity, executable: identity.executable)
        let journal = try SessionJournal(path: path)
        try await journal.add(record)
        do { try await journal.add(record); XCTFail("duplicate must fail") } catch { }
        let loaded = try SessionJournal(path: path)
        let records = await loaded.all()
        XCTAssertEqual(records, [record])
        XCTAssertTrue(record.matches(identity))
        let data = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertFalse(data.contains("environment"))
        XCTAssertFalse(data.contains("arguments"))
        try await loaded.remove(record)
        let empty = await loaded.all()
        XCTAssertTrue(empty.isEmpty)
    }
    func testMalformedJournalIsRejected() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("sessions.json")
        try Data("invalid".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        XCTAssertThrowsError(try SessionJournal(path: file.path))
    }

    func testEncryptedDNSBaselineAndDowngradeSurviveAgentJournalReload() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("sessions.json").path
        let identity = try XCTUnwrap(ProcessIdentity.read(getpid()))
        let record = SessionRecord(identity: identity, executable: identity.executable)
        let journal = try SessionJournal(path: path)
        try await journal.add(record)

        func evidence(_ security: DNSPathEvidence.ResolverSecurity) -> DNSPathEvidence {
            DNSPathEvidence(pid: identity.pid, pidVersion: 1,
                processStartSeconds: identity.startSeconds,
                processStartMicroseconds: identity.startMicroseconds,
                domainClass: .anthropicAPI, transport: .udp,
                resolverIdentity: "8.8.8.8|53", resolverSecurity: security)
        }

        let initialPlaintext = try await journal.observeDNSProtection(evidence(.cleartext))
        XCTAssertEqual(initialPlaintext, false)
        let encryptedBaseline = try await journal.observeDNSProtection(evidence(.dnsOverHTTPS))
        XCTAssertEqual(encryptedBaseline, false)
        let restarted = try SessionJournal(path: path)
        let detectedDowngrade = try await restarted.observeDNSProtection(evidence(.cleartext))
        XCTAssertEqual(detectedDowngrade, true)
        let loaded = await restarted.all()
        XCTAssertEqual(loaded.first?.encryptedDNSDomains, ["anthropicAPI"])
        XCTAssertEqual(loaded.first?.downgradedDNSDomains, ["anthropicAPI"])
        let persisted = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertFalse(persisted.contains("8.8.8.8"))
        XCTAssertFalse(persisted.contains("api.anthropic.com"))
        try await restarted.remove(record)
        let removed = await restarted.all()
        XCTAssertTrue(removed.isEmpty)
    }

    func testAgentRecoverySignalsOnlyRecordedMatchingProcess() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let target = Process()
        target.executableURL = URL(fileURLWithPath: "/bin/sleep")
        target.arguments = ["30"]
        try target.run()
        defer { if target.isRunning { target.terminate() }; target.waitUntilExit() }
        let bystander = Process()
        bystander.executableURL = URL(fileURLWithPath: "/bin/sleep")
        bystander.arguments = ["30"]
        try bystander.run()
        defer { if bystander.isRunning { bystander.terminate() }; bystander.waitUntilExit() }
        let pending = Process()
        pending.executableURL = URL(fileURLWithPath: "/bin/sleep")
        pending.arguments = ["30"]
        try pending.run()
        defer { if pending.isRunning { pending.terminate() }; pending.waitUntilExit() }
        let journal = try SessionJournal(path: root.appendingPathComponent("sessions.json").path)
        let targetIdentity = try XCTUnwrap(ProcessIdentity.read(target.processIdentifier))
        let otherIdentity = try XCTUnwrap(ProcessIdentity.read(bystander.processIdentifier))
        let pendingIdentity = try XCTUnwrap(ProcessIdentity.read(pending.processIdentifier))
        try await journal.add(SessionRecord(identity: targetIdentity, executable: targetIdentity.executable))
        let staleIdentity = ProcessIdentity(pid: otherIdentity.pid, uid: otherIdentity.uid,
            startSeconds: otherIdentity.startSeconds + 1, startMicroseconds: otherIdentity.startMicroseconds,
            executable: otherIdentity.executable)
        try await journal.add(SessionRecord(identity: staleIdentity, executable: otherIdentity.executable))
        // A crash can leave the original launcher alive before exec.
        try await journal.add(SessionRecord(identity: pendingIdentity, executable: "/expected-target"))
        let agent = Process()
        let project = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        agent.executableURL = project.appendingPathComponent(".build/debug/safe-claude-agent")
        agent.arguments = ["--socket", root.appendingPathComponent("agent.sock").path]
        agent.standardOutput = FileHandle.nullDevice
        agent.standardError = FileHandle.nullDevice
        try agent.run()
        defer { if agent.isRunning { agent.terminate() }; agent.waitUntilExit() }
        for _ in 0..<100 {
            if !target.isRunning && !pending.isRunning { break }
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertFalse(target.isRunning)
        XCTAssertFalse(pending.isRunning)
        XCTAssertTrue(bystander.isRunning)
    }
}
