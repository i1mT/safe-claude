import Darwin
import Foundation
import GuardCore
@testable import AgentSupervisorSupport
import XCTest

final class AgentSupervisorTests: XCTestCase {
    @MainActor
    func testSupervisorRestartsAgentAfterCrashOnInjectedSocket() async throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let candidates = [
            root.appendingPathComponent(".build/debug/safe-claude-agent"),
            root.appendingPathComponent(".build/arm64-apple-macosx/debug/safe-claude-agent"),
            root.appendingPathComponent(".build/x86_64-apple-macosx/debug/safe-claude-agent"),
        ]
        let agent = try XCTUnwrap(candidates.first { FileManager.default.isExecutableFile(atPath: $0.path) })
        let directory = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("sc-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }

        let socket = directory.appendingPathComponent("agent.sock").path
        let supervisor = AgentSupervisor(agentExecutable: agent, socketPath: socket,
                                         homeDirectory: directory.path)
        let firstPID = try await waitForReady(supervisor: supervisor, socket: socket)
        XCTAssertEqual(try statusVersion(socket: socket), 1)

        let monitor = Task { await supervisor.monitor(interval: .milliseconds(100)) }
        defer {
            monitor.cancel()
            if let pid = supervisor.supervisedPID { _ = kill(pid, SIGKILL) }
        }

        XCTAssertEqual(kill(firstPID, SIGKILL), 0)
        let secondPID = try await waitForDifferentReady(supervisor: supervisor, socket: socket,
                                                        previousPID: firstPID)
        XCTAssertNotEqual(firstPID, secondPID)
        XCTAssertEqual(try statusVersion(socket: socket), 1)
    }

    @MainActor
    private func waitForReady(supervisor: AgentSupervisor, socket: String) async throws -> pid_t {
        let deadline = ContinuousClock.now + .seconds(15)
        while ContinuousClock.now < deadline {
            if await supervisor.ensureRunning(), let pid = supervisor.supervisedPID,
               (try? statusVersion(socket: socket)) == 1 {
                return pid
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        throw NSError(domain: "AgentSupervisorTests", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "supervised Agent did not become ready on its injected socket"])
    }

    @MainActor
    private func waitForDifferentReady(supervisor: AgentSupervisor, socket: String,
                                      previousPID: pid_t) async throws -> pid_t {
        let deadline = ContinuousClock.now + .seconds(15)
        while ContinuousClock.now < deadline {
            if await supervisor.ensureRunning(), let pid = supervisor.supervisedPID,
               pid != previousPID, (try? statusVersion(socket: socket)) == 1 {
                return pid
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        throw NSError(domain: "AgentSupervisorTests", code: 2,
                      userInfo: [NSLocalizedDescriptionKey: "supervised Agent did not restart after termination"])
    }

    private func statusVersion(socket: String) throws -> Int {
        let fd = try GuardIPC.connect(path: socket)
        defer { close(fd) }
        try GuardIPC.send(GuardRequest(action: "status"), fd: fd)
        return try GuardIPC.receive(GuardResponse.self, fd: fd).version
    }
}
