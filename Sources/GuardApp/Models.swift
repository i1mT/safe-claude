import AppKit
import SwiftUI
import GuardCore
import AgentSupervisorSupport
import UniformTypeIdentifiers

@MainActor
final class MenuModel: ObservableObject {
    @Published var response: GuardResponse?
    @Published var checking = false
    @Published var stale = false
    @Published var minimumScore: Int?
    @Published var runtimeMinimumScore: Int?

    func refresh() {
        guard !checking else { return }
        checking = true
        Task {
            let value = await Task.detached { () -> GuardResponse? in
                try? {
                    let fd = try GuardIPC.connect()
                    defer { close(fd) }
                    try GuardIPC.send(GuardRequest(action: "status"), fd: fd)
                    return try GuardIPC.receive(GuardResponse.self, fd: fd)
                }()
            }.value
            if let policy = try? GuardPolicy.load() {
                minimumScore = policy.minimumScore
                runtimeMinimumScore = policy.runtimeMinimumScore
            } else {
                minimumScore = nil
                runtimeMinimumScore = nil
            }
            if let value, (0...330).contains(Date().timeIntervalSince(value.checkedAt)) {
                response = value
                stale = false
                let notificationsEnabled = (try? GuardPolicy.load().notificationsEnabled) ?? false
                GuardNotificationCoordinator.shared.update(
                    decision: value.decision,
                    enabled: notificationsEnabled
                )
            } else {
                response = nil
                stale = value != nil
                _ = await AgentSupervisor.shared.ensureRunning()
            }
            checking = false
        }
    }
}

@MainActor
final class SettingsModel: ObservableObject {
    @Published var minimumScore = 80
    @Published var runtimeMinimumScore = 80
    @Published var allowIPWho = false
    @Published var allowProxyCheck = false
    @Published var enableUDPCheck = false
    @Published var dnsRequiredProtocol: DNSRequiredProtocol = .anyEncrypted
    @Published var stunEndpoint = STUNProbe.defaultEndpoint
    @Published var trustedEndpointsText = ""
    @Published var forceTerminate = false
    @Published var notificationsEnabled = false
    @Published var providerKey = ""
    @Published var ipAPIKey = ""
    @Published var notice: String?
    @Published var noticeIsError = false
    @Published var sessions: [GuardSessionSummary] = []
    @Published var sessionsLoading = false
    @Published var sessionActionID: String?

    func load() {
        do {
            let policy = try GuardPolicy.load()
            minimumScore = policy.minimumScore
            runtimeMinimumScore = policy.runtimeMinimumScore
            allowIPWho = policy.allowIPWho
            allowProxyCheck = policy.allowProxyCheck
            DNSResolverProbeConsent.setAllowed(policy.allowIPWho)
            enableUDPCheck = policy.enableUDPCheck
            dnsRequiredProtocol = policy.dnsRequiredProtocol
            stunEndpoint = policy.stunEndpoint
            trustedEndpointsText = policy.trustedEndpoints.joined(separator: "\n")
            forceTerminate = policy.forceTerminate
            notificationsEnabled = policy.notificationsEnabled
            notice = nil
        } catch {
            show("无法读取防护策略。请确认 SafeClaude 的本机数据目录可访问。", error: true)
        }
    }

    func savePolicy() {
        do {
            let rawEndpoints = trustedEndpointsText.split(whereSeparator: \.isNewline).map {
                String($0).trimmingCharacters(in: .whitespacesAndNewlines)
            }.filter { !$0.isEmpty }
            guard rawEndpoints.count <= 32,
                  rawEndpoints.allSatisfy({ TrustedEndpoint.canonicalOrigin($0) != nil }) else {
                show("受信 endpoint 仅支持最多 32 个 HTTPS 主机地址；不能包含路径、凭据、查询参数或片段。", error: true)
                return
            }
            try GuardPolicy(minimumScore: minimumScore, runtimeMinimumScore: runtimeMinimumScore,
                            allowIPWho: allowIPWho, allowProxyCheck: allowProxyCheck,
                            enableUDPCheck: enableUDPCheck,
                            stunEndpoint: stunEndpoint, forceTerminate: forceTerminate,
                            dnsRequiredProtocol: dnsRequiredProtocol,
                            notificationsEnabled: notificationsEnabled,
                            trustedEndpoints: rawEndpoints).save()
            DNSResolverProbeConsent.setAllowed(allowIPWho)
            show("防护策略已保存。")
        } catch {
            show("保存失败。请检查本机数据目录权限后重试。", error: true)
        }
    }

    func setNotificationsEnabled(_ enabled: Bool) async {
        let previousValue = notificationsEnabled
        if enabled {
            do {
                try await GuardNotificationCoordinator.shared.requestPermission()
            } catch NotificationSetupError.denied {
                show("通知未获授权。可在 macOS 系统设置的通知中允许 SafeClaude。", error: true)
                return
            } catch {
                show("无法启用桌面通知，请检查 macOS 通知服务后重试。", error: true)
                return
            }
        }
        do {
            var policy = try GuardPolicy.load()
            policy.notificationsEnabled = enabled
            try policy.save()
            notificationsEnabled = enabled
            GuardNotificationCoordinator.shared.setEnabled(enabled)
            show(enabled ? "桌面状态通知已开启。" : "桌面状态通知已关闭。")
        } catch {
            notificationsEnabled = previousValue
            show("通知设置保存失败。请检查本机数据目录权限后重试。", error: true)
        }
    }

    func saveKey() {
        do {
            try GuardSecrets.saveProxyCheckKey(providerKey)
            providerKey = ""
            show("API key 已安全保存到钥匙串。")
        } catch {
            show("保存失败。请检查 key 格式或钥匙串权限。", error: true)
        }
    }

    func removeKey() {
        do {
            try GuardSecrets.deleteProxyCheckKey()
            show("API key 已移除。")
        } catch {
            show("移除失败。", error: true)
        }
    }

    func saveIPAPIKey() {
        do {
            try GuardSecrets.saveIPAPIKey(ipAPIKey)
            ipAPIKey = ""
            show("IP 信誉 API key 已安全保存到钥匙串。")
        } catch {
            show("保存失败。请检查 key 格式或钥匙串权限。", error: true)
        }
    }

    func removeIPAPIKey() {
        do {
            try GuardSecrets.deleteIPAPIKey()
            show("IP 信誉 API key 已移除。")
        } catch {
            show("移除失败。", error: true)
        }
    }

    func clearHistory() async {
        do {
            let fd = try GuardIPC.connect()
            defer { close(fd) }
            try GuardIPC.send(GuardRequest(action: "clear-history"), fd: fd)
            _ = try GuardIPC.receive(GuardResponse.self, fd: fd)
            show("本机网络历史已清除。")
        } catch {
            show("清除失败。请确认后台服务正在运行。", error: true)
        }
    }

    func exportDiagnostics(response: GuardResponse?) {
        guard let response,
              (0...330).contains(Date().timeIntervalSince(response.checkedAt)),
              response.expiresAt.map({ $0 > Date() }) ?? true else {
            show("没有可导出的最新检查结果。请先从菜单栏运行一次检测。", error: true)
            return
        }

        let panel = NSSavePanel()
        panel.title = "导出 SafeClaude 脱敏诊断"
        panel.nameFieldStringValue = "SafeClaude-Diagnostic.json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = false
        guard panel.runModal() == .OK, let destination = panel.url else { return }

        let systemVersion = ProcessInfo.processInfo.operatingSystemVersion
        let report = SanitizedDiagnosticReport(
            response: response,
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0",
            operatingSystem: "\(systemVersion.majorVersion).\(systemVersion.minorVersion).\(systemVersion.patchVersion)"
        )
        do {
            try SanitizedDiagnosticExport.write(report, to: destination)
            show("脱敏诊断已导出。")
        } catch {
            show("导出失败。请检查所选位置的写入权限后重试。", error: true)
        }
    }

    func refreshSessions() {
        guard !sessionsLoading else { return }
        sessionsLoading = true
        Task {
            do {
                let fd = try GuardIPC.connect()
                defer { close(fd) }
                try GuardIPC.send(GuardRequest(action: "sessions"), fd: fd)
                let response = try GuardIPC.receive(GuardResponse.self, fd: fd)
                sessions = response.sessions ?? []
                notice = nil
            } catch {
                show("无法连接后台服务；请确认 Agent 正在运行后重试。", error: true)
            }
            sessionsLoading = false
        }
    }

    func terminateSession(_ session: GuardSessionSummary) {
        guard sessionActionID == nil else { return }
        sessionActionID = session.id
        Task {
            do {
                let fd = try GuardIPC.connect()
                defer { close(fd) }
                try GuardIPC.send(GuardRequest(action: "terminate-session", sessionPID: session.pid,
                    sessionStartSeconds: session.startSeconds,
                    sessionStartMicroseconds: session.startMicroseconds), fd: fd)
                let response = try GuardIPC.receive(GuardResponse.self, fd: fd)
                show(response.reason, error: response.decision != "allow")
                refreshSessions()
            } catch {
                show("结束请求失败；会话可能已退出，请刷新状态。", error: true)
            }
            sessionActionID = nil
        }
    }

    func show(_ text: String, error: Bool = false) {
        notice = text
        noticeIsError = error
    }
}
