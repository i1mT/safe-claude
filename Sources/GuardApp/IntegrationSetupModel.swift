import AppKit
import Foundation
import GuardCore

@MainActor
final class IntegrationSetupModel: ObservableObject {
    @Published private(set) var isIntegrated = false
    @Published private(set) var isBusy = false
    @Published private(set) var statusMessage = ""
    @Published private(set) var statusIsError = false
    @Published var claudeExecutable = ""
    @Published var addShellIntegration = true
    @Published var addClaudeSettingsIntegration = true

    private let dnsEnrollment = DNSProxyEnrollment()
    private let timeEnrollment = NetworkTimeEnrollment()

    private var prefix: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/SafeClaude/installation",
                                    isDirectory: true)
    }

    private var sourceApp: URL { Bundle.main.bundleURL.standardizedFileURL }

    var appCanInstall: Bool {
        sourceApp.path.hasPrefix("/Applications/") || isIntegrated
    }

    private var installerExecutable: URL {
        sourceApp.appendingPathComponent("Contents/Resources/Installer/safe-claude-setup")
    }

    var installerAvailable: Bool {
        FileManager.default.isExecutableFile(atPath: installerExecutable.path)
    }

    var canInstall: Bool {
        !isBusy && !isIntegrated && appCanInstall &&
            installerAvailable && validClaudePath && hasEnabledEntryPoint
    }

    var canUpgrade: Bool {
        !isBusy && isIntegrated && appCanInstall && installerAvailable
    }

    var canUninstall: Bool {
        !isBusy && isIntegrated && installerAvailable
    }

    var hasEnabledEntryPoint: Bool {
        addShellIntegration || addClaudeSettingsIntegration
    }

    var hasValidClaudeExecutable: Bool { validClaudePath }

    init() {
        refresh()
    }

    func refresh() {
        let manifest = prefix.appendingPathComponent("manifest.json")
        isIntegrated = validManifest(at: manifest) &&
            FileManager.default.isExecutableFile(atPath: prefix.appendingPathComponent("bin/claude").path) &&
            FileManager.default.isExecutableFile(atPath: prefix.appendingPathComponent("libexec/safe-claude").path)

        if isIntegrated,
           let selected = InstalledClaude.selectedExecutable(
                targetFile: prefix.appendingPathComponent("libexec/claude-target").path) {
            claudeExecutable = selected
            statusMessage = "Claude Code 已接入 SafeClaude。启动前检查与后台监测已登记。"
            statusIsError = false
        } else {
            if !validClaudePath { claudeExecutable = discoverClaudeExecutable() ?? claudeExecutable }
            if !appCanInstall {
                statusMessage = "请先把 SafeClaude.app 移到 /Applications，再运行首次接入。"
                statusIsError = false
            } else if !installerAvailable {
                statusMessage = "当前 App 缺少集成安装资源，请重新安装完整发行包。"
                statusIsError = true
            } else if claudeExecutable.isEmpty {
                statusMessage = "未找到 Claude Code。请选择 Claude 可执行文件后继续。"
                statusIsError = false
            } else {
                statusMessage = "Claude Code 尚未接入。确认集成范围后即可启用启动保护。"
                statusIsError = false
            }
        }
    }

    func chooseClaudeExecutable() {
        let panel = NSOpenPanel()
        panel.title = "选择 Claude Code 可执行文件"
        panel.message = "选择现有的 Claude Code 文件。SafeClaude 不会修改或替换该文件。"
        panel.prompt = "选择 Claude"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if !claudeExecutable.isEmpty {
            panel.directoryURL = URL(fileURLWithPath: claudeExecutable).deletingLastPathComponent()
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard url.path.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: url.path),
              !url.path.hasPrefix(prefix.appendingPathComponent("bin").path + "/") else {
            statusMessage = "所选文件不可执行，或它是 SafeClaude 自己的启动 shim。"
            statusIsError = true
            return
        }
        claudeExecutable = url.path
        statusMessage = "已选择 Claude Code。安装器会先检查其版本和文件身份。"
        statusIsError = false
    }

    func install() {
        guard canInstall else { return }
        var arguments = ["install"]
        appendSharedArguments(to: &arguments)
        if !addShellIntegration { arguments.append("--no-shell") }
        if !addClaudeSettingsIntegration { arguments.append("--no-settings") }
        runInstaller(arguments: arguments, successMessage: "Claude Code 已接入。重新打开终端后，启动命令会经过 SafeClaude 检查。")
    }

    func upgrade() {
        guard canUpgrade else { return }
        var arguments = ["upgrade"]
        appendSharedArguments(to: &arguments)
        runInstaller(arguments: arguments, successMessage: "SafeClaude 集成已升级，原有 Claude 设置已保留。")
    }

    func uninstall() {
        guard canUninstall else { return }
        isBusy = true
        statusMessage = "正在暂停新会话并确认现有会话已结束。"
        statusIsError = false

        let cli = prefix.appendingPathComponent("libexec/safe-claude")
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let customConfig = ProcessInfo.processInfo.environment["CLAUDE_CONFIG_DIR"]
        let env = TaskEnvironment(home: home, customConfig: customConfig)

        Task {
            guard let drain = await executeAgentAction("prepare-uninstall", cli: cli),
                  drain.decision == "allow", drain.managedSessions == 0 else {
                isBusy = false
                statusMessage = "无法确认所有受管会话已结束。为保持防护，未撤销系统服务或删除集成；关闭受管 Claude 会话并恢复后台服务后重试。"
                statusIsError = true
                return
            }

            do {
                try await dnsEnrollment.removeForUninstall()
            } catch {
                await cancelAgentDrain(cli)
                isBusy = false
                statusMessage = "macOS 尚未确认 DNS 扩展已撤销。SafeClaude 安装与服务文件均已保留；完成系统授权或重启后可重试。"
                statusIsError = true
                return
            }
            do {
                try await timeEnrollment.unregisterForUninstall()
            } catch {
                await cancelAgentDrain(cli)
                isBusy = false
                statusMessage = "校时服务或其状态文件尚未确认安全清理。SafeClaude 安装与服务文件均已保留；检查系统后台项目授权后可重试。DNS 监测已停用，可在网络设置中重新启用。"
                statusIsError = true
                return
            }

            statusMessage = "系统级服务已撤销，正在检查配置并移除用户级集成。"
            let result = await executeSetup(
                executable: installerExecutable,
                actionArguments: ["uninstall", "--managed-ui"],
                environment: env)
            isBusy = false
            if result.exitCode == 0 {
                refresh()
                statusMessage = "SafeClaude 集成已移除，Claude Code 和其他设置已保留。"
                statusIsError = false
            } else {
                await cancelAgentDrain(cli)
                statusMessage = "系统级监测服务已撤销，但用户级集成仍保留。修复后可重试卸载：\(SetupErrorMessage.sanitized(result.stderr))"
                statusIsError = true
            }
        }
    }

    private var validClaudePath: Bool {
        claudeExecutable.hasPrefix("/") &&
            FileManager.default.isExecutableFile(atPath: claudeExecutable) &&
            !claudeExecutable.hasPrefix(prefix.appendingPathComponent("bin").path + "/")
    }

    private func appendSharedArguments(to arguments: inout [String]) {
        arguments += ["--source-app", sourceApp.path, "--claude", claudeExecutable]
    }

    private func runInstaller(arguments: [String], successMessage: String) {
        guard installerAvailable else {
            refresh()
            return
        }
        isBusy = true
        statusMessage = arguments.first == "upgrade" ? "正在验证现有集成并准备升级。" : "正在检查并安装本机集成。"
        statusIsError = false

        let executable = installerExecutable
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let customConfig = ProcessInfo.processInfo.environment["CLAUDE_CONFIG_DIR"]
        let env = TaskEnvironment(home: home, customConfig: customConfig)

        Task {
            let result = await executeSetup(executable: executable,
                                            actionArguments: arguments, environment: env)
            isBusy = false
            if result.exitCode == 0 {
                refresh()
                statusMessage = successMessage
                statusIsError = false
            } else {
                statusMessage = SetupErrorMessage.sanitized(result.stderr)
                statusIsError = true
            }
        }
    }

    private func cancelAgentDrain(_ cli: URL) async {
        _ = await executeAgentAction("cancel-uninstall", cli: cli)
    }

    private func executeAgentAction(_ action: String, cli: URL) async -> GuardResponse? {
        await Task.detached(priority: .userInitiated) {
            let process = Process()
            let output = Pipe()
            process.executableURL = cli
            process.arguments = [action]
            process.environment = [
                "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
            ]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                guard process.terminationStatus == 0 else { return nil }
                return try JSONDecoder().decode(GuardResponse.self, from: data)
            } catch {
                return nil
            }
        }.value
    }

    private func validManifest(at url: URL) -> Bool {
        guard let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["version"] as? Int == 1,
              object["files"] as? [String: String] != nil else { return false }
        return true
    }

    private func discoverClaudeExecutable() -> String? {
        let fileManager = FileManager.default
        var candidates = (ProcessInfo.processInfo.environment["PATH"] ?? "")
            .split(separator: ":")
            .map { URL(fileURLWithPath: String($0), isDirectory: true).appendingPathComponent("claude").path }
        let home = fileManager.homeDirectoryForCurrentUser
        candidates += [
            home.appendingPathComponent(".local/bin/claude").path,
            URL(fileURLWithPath: "/opt/homebrew/bin/claude").path,
            URL(fileURLWithPath: "/usr/local/bin/claude").path,
        ]
        let shim = prefix.appendingPathComponent("bin/claude").standardizedFileURL.path
        return candidates.first {
            $0 != shim && !$0.hasPrefix(prefix.appendingPathComponent("bin").path + "/") &&
                fileManager.isExecutableFile(atPath: $0)
        }
    }
}

private struct TaskEnvironment: Sendable {
    let home: String
    let customConfig: String?

    var values: [String: String] {
        var result = ["HOME": home, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"]
        if let customConfig, !customConfig.isEmpty { result["CLAUDE_CONFIG_DIR"] = customConfig }
        return result
    }
}

private struct SetupProcessResult: Sendable {
    let exitCode: Int32
    let stderr: String
}

private func executeSetup(executable: URL, actionArguments: [String],
                          environment: TaskEnvironment) async -> SetupProcessResult {
    await Task.detached(priority: .userInitiated) {
        let process = Process()
        let errorPipe = Pipe()
        process.executableURL = executable
        process.arguments = actionArguments
        process.environment = environment.values
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errorPipe
        do {
            try process.run()
            let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let message = String(decoding: data.prefix(8192), as: UTF8.self)
            return SetupProcessResult(exitCode: process.terminationStatus, stderr: message)
        } catch {
            return SetupProcessResult(exitCode: 127, stderr: error.localizedDescription)
        }
    }.value
}

private enum SetupErrorMessage {
    static func sanitized(_ raw: String) -> String {
        let message = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !message.isEmpty else { return "操作未完成。请确认 Claude Code 可执行文件与本机安装权限后重试。" }
        return String(message.suffix(1800))
    }
}
