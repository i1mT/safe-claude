import Darwin
import Foundation
import GuardCore
import Security

private final class NetworkTimeStatusDaemon: NSObject, NSXPCListenerDelegate,
                                             NetworkTimeStatusServiceProtocol, @unchecked Sendable {
    private let queue = DispatchQueue(label: "local.safeclaude.time-status")
    private var timer: DispatchSourceTimer?

    func start() {
        guard let requirement = peerCodeSigningRequirement() else {
            fputs("SafeClaude time service refused to start without a valid signed app identity.\n", stderr)
            exit(EXIT_FAILURE)
        }
        let listener = NSXPCListener(machServiceName: NetworkTimeStatusService.machServiceName)
        listener.setConnectionCodeSigningRequirement(requirement)
        listener.delegate = self
        queue.async { self.startMonitoringLocked() }
        listener.resume()
        dispatchMain()
    }

    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(
            with: NetworkTimeStatusServiceProtocol.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func prepareForUninstall(reply: @escaping (Bool) -> Void) {
        let completion = DaemonReply(reply)
        queue.async {
            self.timer?.cancel()
            self.timer = nil
            do {
                completion.send(try NetworkTimeStatus.remove())
            } catch {
                self.startMonitoringLocked()
                completion.send(false)
            }
        }
    }

    func resumeMonitoring(reply: @escaping (Bool) -> Void) {
        let completion = DaemonReply(reply)
        queue.async {
            self.startMonitoringLocked()
            completion.send(self.timer != nil)
        }
    }

    private func startMonitoringLocked() {
        guard timer == nil else { return }
        sampleNetworkTime()
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + .seconds(60), repeating: .seconds(60),
                        leeway: .seconds(5))
        source.setEventHandler { [weak self] in self?.sampleNetworkTime() }
        timer = source
        source.resume()
    }

    private func sampleNetworkTime() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/systemsetup")
        process.arguments = ["-getusingnetworktime"]
        process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            let deadline = Date().addingTimeInterval(5)
            while process.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if process.isRunning {
                process.terminate()
                let terminationDeadline = Date().addingTimeInterval(0.5)
                while process.isRunning && Date() < terminationDeadline {
                    Thread.sleep(forTimeInterval: 0.025)
                }
                if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
                process.waitUntilExit()
                throw HelperError.timedOut
            }
            let data = output.fileHandleForReading.readDataToEndOfFile()
            let value = NetworkTimeStatus.parseSystemSetup(
                output: String(decoding: data.prefix(4097), as: UTF8.self),
                exitCode: process.terminationStatus)
            try NetworkTimeStatus.write(NetworkTimeStatusSnapshot(value: value ?? .unavailable))
        } catch {
            try? NetworkTimeStatus.write(NetworkTimeStatusSnapshot(value: .unavailable))
        }
    }

    private func peerCodeSigningRequirement() -> String? {
        guard let executable = Bundle.main.executableURL?.resolvingSymlinksInPath() else {
            return nil
        }
        guard let appURL = containingAppBundle(for: executable) else { return nil }
        var ownCode: SecCode?
        guard
              let bundleIdentifier = Bundle(url: appURL)?.bundleIdentifier,
              SecCodeCopySelf(SecCSFlags(), &ownCode) == errSecSuccess,
              let ownCode,
              SecCodeCheckValidity(ownCode, SecCSFlags(), nil) == errSecSuccess,
              let ownTeam = signingTeam(of: ownCode),
              let appCode = staticCode(at: appURL),
              SecStaticCodeCheckValidity(appCode, SecCSFlags(), nil) == errSecSuccess,
              let appIdentity = signingIdentity(of: appCode),
              appIdentity.identifier == bundleIdentifier,
              appIdentity.team == ownTeam else {
            return nil
        }
        return NetworkTimeServiceRequirement.make(
            bundleIdentifier: bundleIdentifier, teamIdentifier: ownTeam)
    }

    private func containingAppBundle(for executable: URL) -> URL? {
        var parent = executable.deletingLastPathComponent()
        while parent.path != "/" {
            if parent.pathExtension == "app" {
                return parent.resolvingSymlinksInPath()
            }
            parent.deleteLastPathComponent()
        }
        return nil
    }

    private func staticCode(at url: URL) -> SecStaticCode? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &code) == errSecSuccess else {
            return nil
        }
        return code
    }

    private func signingTeam(of code: SecCode) -> String? {
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else {
            return nil
        }
        return signingIdentity(of: staticCode)?.team
    }

    private func signingIdentity(of code: SecStaticCode) -> (identifier: String, team: String)? {
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String else {
            return nil
        }
        return (identifier, team)
    }
}

private struct DaemonReply: @unchecked Sendable {
    let callback: (Bool) -> Void

    init(_ callback: @escaping (Bool) -> Void) {
        self.callback = callback
    }

    func send(_ result: Bool) {
        callback(result)
    }
}

private enum HelperError: Error {
    case timedOut
}

private let daemon = NetworkTimeStatusDaemon()
daemon.start()
