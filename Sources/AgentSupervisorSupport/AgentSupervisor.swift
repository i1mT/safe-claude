import Darwin
import Foundation
import GuardCore

/// Starts the bundled Agent when no independently managed Agent is available.
/// The child receives a deliberately small environment and can outlive the
/// menu bar process, so Claude credentials from a GUI launch context are never
/// inherited by the Agent.
@MainActor
public final class AgentSupervisor {
    public static let shared = AgentSupervisor()

    private let configuredAgentExecutable: URL?
    private let socketPath: String
    private let homeDirectory: String
    private var process: Process?
    private var starting = false

    public init(
        agentExecutable: URL? = nil,
        socketPath: String = GuardIPC.socketPath,
        homeDirectory: String = NSHomeDirectory()
    ) {
        configuredAgentExecutable = agentExecutable
        self.socketPath = socketPath
        self.homeDirectory = homeDirectory
    }

    public func monitor(interval: Duration = .seconds(5)) async {
        while !Task.isCancelled {
            _ = await ensureRunning()
            try? await Task.sleep(for: interval)
        }
    }

    @discardableResult
    public func ensureRunning() async -> Bool {
        if canConnect() { return true }
        if let process, process.isRunning { return false }
        guard !starting else { return false }
        starting = true
        defer { starting = false }

        guard let executable = configuredAgentExecutable ?? bundledAgentExecutable(),
              FileManager.default.isExecutableFile(atPath: executable.path) else { return false }

        let child = Process()
        child.executableURL = executable
        child.arguments = ["--socket", socketPath]
        child.environment = [
            "HOME": homeDirectory,
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
        ]
        child.currentDirectoryURL = URL(fileURLWithPath: homeDirectory, isDirectory: true)
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        child.terminationHandler = { [weak self, weak child] _ in
            Task { @MainActor in
                guard let self, self.process === child else { return }
                self.process = nil
            }
        }

        do {
            try child.run()
            process = child
        } catch {
            return false
        }

        for _ in 0..<20 {
            if canConnect() { return true }
            try? await Task.sleep(for: .milliseconds(100))
            if !child.isRunning { return false }
        }
        return canConnect()
    }

    var supervisedPID: pid_t? { process?.isRunning == true ? process?.processIdentifier : nil }

    private func canConnect() -> Bool {
        guard let fd = try? GuardIPC.connect(path: socketPath) else { return false }
        close(fd)
        return true
    }

    private func bundledAgentExecutable() -> URL? {
        guard let current = ProcessIdentity.read(getpid())?.executable else { return nil }
        return URL(fileURLWithPath: current)
            .deletingLastPathComponent()
            .appendingPathComponent("safe-claude-agent")
    }
}
