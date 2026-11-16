import Darwin
import Foundation
import XCTest
@testable import GuardCore

final class GuardIPCTests: XCTestCase {
    func testBoundedReadRejectsDataBeyondLimit() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        try Data("hello".utf8).write(to: file)
        let fd = open(file.path, O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { close(fd) }
        XCTAssertThrowsError(try BoundedFile.read(fd, maximum: 4))
        XCTAssertEqual(lseek(fd, 0, SEEK_SET), 0)
        XCTAssertEqual(try BoundedFile.read(fd, maximum: 5), Data("hello".utf8))
    }
    func testNamedPipesDoNotBlockConfigurationReaders() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let fifo = root.appendingPathComponent("pipe").path
        XCTAssertEqual(mkfifo(fifo, 0o600), 0)
        XCTAssertThrowsError(try GuardPolicy.load(path: fifo))
        XCTAssertThrowsError(try SessionJournal(path: fifo))
        XCTAssertThrowsError(try HistoryTracker(persistentPath: fifo, keyData: Data(repeating: 1, count: 32)))
        XCTAssertNil(ClientCertificate.inspect(path: fifo))
        XCTAssertNil(InstalledClaude.selectedExecutable(targetFile: fifo))
    }
    func testUnknownRuleIdentifiersAreOptionalAndRoundTrip() throws {
        let sampleTime = Date(timeIntervalSince1970: 1_700_000_123)
        let response = GuardResponse(decision: "hold", unknownCount: 2, unknownRules: ["A01", "D02"], reason: "pending",
            ruleStatuses: [RuleReportStatus(rule: "A01", status: "unknown", observedAt: sampleTime),
                           RuleReportStatus(rule: "A02", status: "passed")],
            assessmentContext: .claudeLaunch)
        let decoded = try JSONDecoder().decode(GuardResponse.self, from: JSONEncoder().encode(response))
        XCTAssertEqual(decoded.unknownRules, ["A01", "D02"])
        XCTAssertEqual(decoded.ruleStatuses?.map(\.status), ["unknown", "passed"])
        XCTAssertEqual(decoded.ruleStatuses?.first?.observedAt, sampleTime)
        XCTAssertEqual(decoded.assessmentContext, .claudeLaunch)
        let legacy = Data(#"{"version":1,"decision":"hold","unknownCount":0,"reason":"pending","findings":[],"checkedAt":0}"#.utf8)
        XCTAssertNil(try JSONDecoder().decode(GuardResponse.self, from: legacy).unknownRules)
        XCTAssertNil(try JSONDecoder().decode(GuardResponse.self, from: legacy).ruleStatuses)
        XCTAssertNil(try JSONDecoder().decode(GuardResponse.self, from: legacy).assessmentContext)
        let priorRuleStatus = Data(#"{"version":1,"decision":"hold","unknownCount":0,"reason":"pending","findings":[],"checkedAt":0,"ruleStatuses":[{"rule":"A01","status":"unknown","points":0}]}"#.utf8)
        XCTAssertNil(try JSONDecoder().decode(GuardResponse.self, from: priorRuleStatus)
            .ruleStatuses?.first?.observedAt)
        XCTAssertNil(try JSONDecoder().decode(GuardResponse.self, from: priorRuleStatus)
            .ruleStatuses?.first?.remediation)
        let reportStatus = RuleReportStatus(
            rule: "A01", status: "unknown", source: "collector-gap-A01",
            remediation: "修复网络路径并重新评估"
        )
        let encodedStatus = try JSONEncoder().encode(reportStatus)
        let decodedStatus = try JSONDecoder().decode(RuleReportStatus.self, from: encodedStatus)
        XCTAssertEqual(decodedStatus.remediation, "修复网络路径并重新评估")
    }
    func testSessionSummaryIPCContainsOnlyDisplayFields() throws {
        let summary = GuardSessionSummary(pid: 42, startSeconds: 123, startMicroseconds: 4,
            isTopLevel: true, decision: "allow", safetyScore: 91, checkedAt: Date(timeIntervalSince1970: 10))
        let response = GuardResponse(decision: "allow", reason: "sessions", sessions: [summary])
        let data = try JSONEncoder().encode(response)
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(text.contains("\"pid\":42"))
        XCTAssertFalse(text.contains("executable"))
        XCTAssertFalse(text.contains("arguments"))
        XCTAssertFalse(text.contains("workingDirectory"))
        XCTAssertNil(try JSONDecoder().decode(GuardResponse.self,
            from: #"{"version":1,"decision":"hold","unknownCount":0,"reason":"pending","findings":[],"checkedAt":0}"#.data(using: .utf8)!).sessions)
    }
    func testBoundedProtocolRoundTripAndIdentity() throws {
        var pair: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { close(pair[0]); close(pair[1]) }
        try GuardIPC.configureClient(pair[0])
        XCTAssertEqual(try GuardIPC.peerPID(pair[0]), getpid())
        let request = GuardRequest(action: "preflight", environment: ["TZ": "UTC"], executable: "/bin/true")
        try GuardIPC.send(request, fd: pair[0])
        let decoded = try GuardIPC.receive(GuardRequest.self, fd: pair[1])
        XCTAssertEqual(decoded.action, "preflight")
        XCTAssertEqual(decoded.environment?["TZ"], "UTC")
        XCTAssertEqual(decoded.executable, "/bin/true")
        XCTAssertThrowsError(try GuardIPC.send(GuardRequest(action: String(repeating: "x", count: 40_000)), fd: pair[0]))
    }
    func testLaunchCaptureDoesNotIncludeUnrelatedSecrets() throws {
        setenv("ANTHROPIC_API_KEY", "test-private-key", 1)
        defer { unsetenv("ANTHROPIC_API_KEY") }
        XCTAssertNil(CurrentAssessment.captureEnvironment()["ANTHROPIC_API_KEY"])
        let mode = AuthenticationContext.processMode()
        XCTAssertTrue(mode?.contains("api-key") == true)
        let request = GuardRequest(action: "preflight", authenticationContext: mode)
        let encoded = String(data: try JSONEncoder().encode(request), encoding: .utf8)!
        XCTAssertFalse(encoded.contains("test-private-key"))
    }
    func testInvalidFrameRejected() throws {
        var pair: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { close(pair[0]); close(pair[1]) }
        let data: [UInt8] = [0, 1, 0, 0]
        XCTAssertEqual(data.withUnsafeBytes { Darwin.write(pair[0], $0.baseAddress, $0.count) }, 4)
        XCTAssertThrowsError(try GuardIPC.receive(GuardRequest.self, fd: pair[1]))
    }
    func testDirectoryRejectsInsecurePermissionsAndSymlink() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let insecure = root.appendingPathComponent("insecure")
        try FileManager.default.createDirectory(at: insecure, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: insecure.path)
        XCTAssertThrowsError(try GuardIPC.prepareDirectory(insecure.path))
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: insecure)
        XCTAssertThrowsError(try GuardIPC.prepareDirectory(link.path))
    }
    func testProcessIdentityIncludesStartAndExecutable() throws {
        let identity = try XCTUnwrap(ProcessIdentity.read(getpid()))
        XCTAssertEqual(identity.uid, getuid())
        XCTAssertTrue(identity.stillMatches())
        XCTAssertNil(ProcessIdentity.read(-1))
        XCTAssertEqual(ProcessIdentity.parentPID(of: getpid()), getppid())
    }
    func testOnlyMatchingProcessIdentityReceivesSignal() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["30"]
        try process.run()
        defer { if process.isRunning { process.terminate() }; process.waitUntilExit() }
        let identity = try XCTUnwrap(ProcessIdentity.read(process.processIdentifier))
        let reusedPID = ProcessIdentity(pid: identity.pid, uid: identity.uid,
            startSeconds: identity.startSeconds + 1, startMicroseconds: identity.startMicroseconds,
            executable: identity.executable)
        XCTAssertFalse(reusedPID.signal(SIGTERM))
        XCTAssertTrue(process.isRunning)
        XCTAssertTrue(identity.signal(SIGTERM))
    }
}
