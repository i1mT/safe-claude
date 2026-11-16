import SwiftUI
import GuardCore

struct ManagedSessionsPage: View {
    @ObservedObject var model: SettingsModel
    @State private var sessionToEnd: GuardSessionSummary?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("本机受管进程", systemImage: "lock.shield")
                    .guardFont(size: 15, weight: .bold)
                    .foregroundStyle(SettingsPalette.text)
                Spacer()
                Button {
                    model.refreshSessions()
                } label: {
                    Label("刷新", systemImage: "arrow.clockwise")
                }
                .buttonStyle(SecondaryButtonStyle())
                .accessibilityLabel(model.sessionsLoading ? "正在刷新受管会话列表" : "刷新受管会话列表")
                .disabled(model.sessionsLoading)
            }
            if model.sessionsLoading && model.sessions.isEmpty {
                ProgressView("正在读取 Agent 状态…").guardFont(size: 13).padding(.vertical, 18)
            } else if model.sessions.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "terminal").font(.system(size: 21)).foregroundStyle(SettingsPalette.accent)
                    Text("当前没有受管会话").guardFont(size: 14, weight: .semibold).foregroundStyle(SettingsPalette.text)
                    Text("通过 SafeClaude 启动并通过检查的 Claude Code 会显示在这里。")
                        .guardFont(size: 12).foregroundStyle(SettingsPalette.muted)
                }
                .frame(maxWidth: .infinity).padding(.vertical, 18)
            } else {
                ForEach(model.sessions) { session in
                    HStack(spacing: 12) {
                        Circle().fill(session.decision == "hold" ? SettingsPalette.danger : MenuPalette.accentInk)
                            .frame(width: 8, height: 8)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(session.isTopLevel ? "Claude Code 主会话" : "Claude Code 子进程")
                                .guardFont(size: 14, weight: .semibold).foregroundStyle(SettingsPalette.text)
                            Text("PID \(session.pid) · \(sessionStatus(session))")
                                .guardFont(size: 12, design: .monospaced)
                                .foregroundStyle(SettingsPalette.muted)
                        }
                        Spacer()
                        if let score = session.safetyScore {
                            Text("\(score)").guardFont(size: 15, weight: .bold, design: .rounded)
                                .monospacedDigit().foregroundStyle(SettingsPalette.text)
                            Text("分").guardFont(size: 11).foregroundStyle(SettingsPalette.muted)
                        }
                        Button(role: .destructive) {
                            sessionToEnd = session
                        } label: {
                            if model.sessionActionID == session.id { ProgressView().controlSize(.small) }
                            else { Text("结束会话") }
                        }
                        .buttonStyle(SecondaryButtonStyle())
                        .accessibilityLabel(model.sessionActionID == session.id
                                           ? "正在结束 Claude Code 会话，进程号 \(session.pid)"
                                           : "结束 Claude Code 会话，进程号 \(session.pid)")
                        .accessibilityHint("结束前 Agent 会重新核对进程身份")
                        .disabled(model.sessionActionID != nil)
                    }
                    .padding(.vertical, 13)
                    .overlay(alignment: .bottom) {
                        Rectangle().fill(SettingsPalette.line).frame(height: 1)
                    }
                }
            }
            Text("列表仅展示进程号、会话类型和检查状态；不会读取命令参数、工作目录或会话内容。结束操作会由 Agent 再次核对进程启动身份。")
                .guardFont(size: 12).foregroundStyle(SettingsPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 8)
        .onAppear(perform: model.refreshSessions)
        .confirmationDialog("结束 Claude Code 会话？", isPresented: Binding(
            get: { sessionToEnd != nil }, set: { if !$0 { sessionToEnd = nil } }
        ), titleVisibility: .visible) {
            if let session = sessionToEnd {
                Button("结束 PID \(session.pid)", role: .destructive) {
                    model.terminateSession(session)
                    sessionToEnd = nil
                }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text(model.forceTerminate
                 ? "Agent 将先请求会话正常退出；若进程仍存活，会按当前策略在宽限期后强制结束。"
                 : "Agent 将请求会话退出并等待；强制结束策略当前关闭，未退出时会报告失败。")
        }
    }

    private func sessionStatus(_ session: GuardSessionSummary) -> String {
        switch session.decision {
        case "allow": return "受保护"
        case "warning": return "需留意"
        case "hold": return "处置中"
        default: return "检查中"
        }
    }
}

struct ProtectionSettingsPage: View {
    @ObservedObject var model: SettingsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Rectangle().fill(SettingsPalette.line).frame(height: 1)
            ThresholdSettingRow(
                title: "启动安全门槛",
                detail: "低于此分数时，Claude Code 将无法启动。",
                value: $model.minimumScore
            )
            SettingsDivider()
            ThresholdSettingRow(
                title: "运行中安全门槛",
                detail: "运行中跌破门槛后，Agent 按策略处置该会话。",
                value: $model.runtimeMinimumScore
            )
            SettingsDivider()
            ToggleSettingRow(
                title: "会话未退出时强制结束",
                detail: "启用后，在宽限信号后仍未退出的受管进程会被强制结束。",
                value: $model.forceTerminate
            )
            HStack {
                Text("安全分范围 0–100 · 分数越高越安全")
                    .guardFont(size: 12, weight: .medium)
                    .foregroundStyle(SettingsPalette.muted)
                Spacer()
                Button("保存防护策略", action: model.savePolicy)
                    .buttonStyle(AccentButtonStyle())
            }
            .padding(.top, 18)
            Rectangle().fill(SettingsPalette.line).frame(height: 1).padding(.top, 18)
        }
        .padding(.vertical, 8)
    }
}

struct NetworkPrivacySettingsPage: View {
    @ObservedObject var model: SettingsModel
    @StateObject private var dnsEnrollment = DNSProxyEnrollment()
    @StateObject private var timeEnrollment = NetworkTimeEnrollment()
    @State private var dnsAction: DNSAction?

    private enum DNSAction: String, Identifiable {
        case enable, disable
        var id: String { rawValue }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Rectangle().fill(SettingsPalette.line).frame(height: 1)
            networkTimeControl
            SettingsDivider()
            dnsProxyControl
            SettingsDivider()
            dnsEncryptionLock
            SettingsDivider()
            ToggleSettingRow(
                title: "允许 ProxyCheck 信誉查询",
                detail: "开启后，SafeClaude 会将 Claude API 出口公网 IP 发送至 ProxyCheck，查询代理、VPN、Tor、机房与信誉风险。无需 API key，每日最多 100 次；使用已保存的 key 时额度更高。供应商会记录查询方 IP 计算匿名额度；使用 key 时最多保留 24 小时。关闭时不会向该服务发送地址，对应信誉项保持待确认。",
                value: $model.allowProxyCheck
            )
            SettingsDivider()
            ToggleSettingRow(
                title: "允许 IPWho 地理查询",
                detail: "查询 Claude HTTP 出口与 DNS 递归出口的国家/时区。相关公网 IP 会发送至 IPWho；DNS 检查只发送固定 whoami TXT 查询。支持 port 53 UDP、port 853 DoT，以及系统配置明确提供 endpoint 的 DoH。短期共享证据只含国家码和解析器摘要；关闭后 D02 未知，多 resolver 时 D03 未知并阻断。",
                value: $model.allowIPWho
            )
            SettingsDivider()
            ToggleSettingRow(
                title: "检查 TCP 与 UDP 出口国家",
                detail: "向配置的 STUN 服务发送 UDP Binding 请求，并将映射公网 IP 发送至 IPWho 查询国家。需同时启用 IPWho；关闭时不进行 UDP 探测。",
                value: $model.enableUDPCheck
            )
            VStack(alignment: .leading, spacing: 6) {
                Text("STUN 服务地址").guardFont(size: 13, weight: .semibold).foregroundStyle(SettingsPalette.text)
                TextField("主机名:端口", text: $model.stunEndpoint)
                    .guardInput()
                    .disabled(!model.enableUDPCheck)
                Text("默认 stun.cloudflare.com:3478。STUN 服务会看到你的公网 IP；仅支持主机名与 UDP 端口。")
                    .guardFont(size: 12).foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 12)
            VStack(alignment: .leading, spacing: 6) {
                Text("受信 API endpoint").guardFont(size: 13, weight: .semibold).foregroundStyle(SettingsPalette.text)
                TextEditor(text: $model.trustedEndpointsText)
                    .font(.system(size: 12, design: .monospaced))
                    .frame(minHeight: 72, maxHeight: 120)
                    .scrollContentBackground(.hidden)
                    .padding(6)
                    .background(SettingsPalette.row, in: RoundedRectangle(cornerRadius: 8))
                Text("每行一个 HTTPS origin，例如 https://gateway.example:8443。官方 api.anthropic.com 默认受信；仅精确匹配主机与端口。")
                    .guardFont(size: 12).foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 14)
            HStack {
                Text("查询设置会用于启动检查和运行中复核。")
                    .guardFont(size: 12)
                    .foregroundStyle(SettingsPalette.muted)
                Spacer()
                Button("保存网络设置", action: model.savePolicy)
                    .buttonStyle(AccentButtonStyle())
            }
            .padding(.top, 18)
            Rectangle().fill(SettingsPalette.line).frame(height: 1).padding(.top, 18)
        }
        .padding(.vertical, 8)
        .onAppear {
            Task { await dnsEnrollment.refresh() }
        }
        .task {
            while !Task.isCancelled {
                timeEnrollment.refresh()
                try? await Task.sleep(for: .seconds(5))
            }
        }
        .confirmationDialog(
            dnsAction == .enable ? "启用 SafeClaude DNS flow 监测？" : "停用 SafeClaude DNS flow 监测？",
            isPresented: Binding(
                get: { dnsAction != nil },
                set: { if !$0 { dnsAction = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let action = dnsAction {
                Button(action == .enable ? "继续并请求 macOS 授权" : "移除 SafeClaude DNS 配置",
                       role: action == .disable ? .destructive : nil) {
                    Task {
                        if action == .enable { await dnsEnrollment.enable() }
                        else { await dnsEnrollment.disable() }
                        dnsAction = nil
                    }
                }
            }
            Button("取消", role: .cancel) { dnsAction = nil }
        } message: {
            if dnsAction == .enable {
                Text("SafeClaude DNS Proxy 会处理本机 DNS flow，macOS 可能停用其他应用的 DNS Proxy。停用 SafeClaude 后，其他 DNS Proxy 不一定会自动恢复。D01–D04 需要该进程的实际 DNS flow；首次观测或策略无法确认时会阻断启动。")
            } else {
                Text("只移除 SafeClaude 的 DNS Proxy 配置。若之前有其他 DNS Proxy，请在系统设置中检查并重新启用。")
            }
        }
    }

    private var networkTimeControl: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "clock.badge.checkmark")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(SettingsPalette.accent)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 5) {
                    Text("自动网络校时状态")
                        .guardFont(size: 14, weight: .semibold)
                        .foregroundStyle(SettingsPalette.text)
                    Text(networkTimeDescription)
                        .guardFont(size: 12)
                        .foregroundStyle(SettingsPalette.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                networkTimeAction
            }
        }
        .padding(.vertical, 12)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private var networkTimeAction: some View {
        switch timeEnrollment.state {
        case .enabled:
            Button("停用读取") { timeEnrollment.disable() }
                .buttonStyle(SecondaryButtonStyle())
                .accessibilityHint("安全移除校时状态快照并注销 SafeClaude 的系统级只读校时服务")
        case .checking:
            ProgressView().controlSize(.small).accessibilityLabel("正在读取网络校时服务状态")
        case .approvalRequired:
            Button("刷新批准状态") { timeEnrollment.refresh() }
                .buttonStyle(SecondaryButtonStyle())
        case .notRegistered, .unavailable:
            Button("启用并授权") { timeEnrollment.enable() }
                .buttonStyle(AccentButtonStyle())
                .disabled(timeEnrollment.state == .unavailable)
        case .failed:
            if timeEnrollment.serviceIsRegistered {
                Button("重试停用") { timeEnrollment.disable() }
                    .buttonStyle(SecondaryButtonStyle())
            } else {
                Button("重试授权") { timeEnrollment.enable() }
                    .buttonStyle(AccentButtonStyle())
            }
        }
    }

    private var networkTimeDescription: String {
        switch timeEnrollment.state {
        case .checking:
            return "正在检查特权读取服务。服务未就绪时，此项保持未知并阻断。"
        case .notRegistered:
            return "尚未授权读取系统校时开关。启用后 macOS 会要求管理员批准；SafeClaude 只读取状态，不会更改系统时间设置。"
        case .approvalRequired:
            return "服务等待系统批准。完成 macOS 的后台项目授权后，重新打开此页检查状态。"
        case .unavailable:
            return "此安装包缺少校时读取服务，E08 保持未知并阻断。"
        case .failed:
            return "服务操作或状态文件清理失败，E08 保持未知并阻断。检查后台项目授权后重试；若服务仍启用，可再次停用。"
        case .enabled(let snapshot):
            guard let snapshot else {
                return "服务已启用，正在等待首次校时状态采样；采样完成前 E08 保持未知并阻断。"
            }
            switch snapshot.value {
            case .enabled:
                return "最近采样：自动网络校时已开启。状态每分钟复核一次，SafeClaude 不会更改系统时间设置。"
            case .disabled:
                return "最近采样：自动网络校时已关闭，E08 已计分。请在系统设置中开启自动设置日期与时间。"
            case .unavailable:
                return "最近采样未能读取系统开关，E08 保持未知并阻断。请确认系统授权后重试。"
            }
        }
    }

    private var dnsEncryptionLock: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(SettingsPalette.accent)
                    .frame(width: 30, height: 30)
                    .background(SettingsPalette.successBackground, in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 4) {
                    Text("锁定 Claude DNS 加密协议")
                        .guardFont(size: 14, weight: .semibold)
                        .foregroundStyle(SettingsPalette.text)
                    Text("活动 DNS 设置必须符合这里的锁定值。明文、协议不符或无法确认时会计分并阻断。")
                        .guardFont(size: 12)
                        .foregroundStyle(SettingsPalette.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }

            HStack(spacing: 6) {
                ForEach(DNSRequiredProtocol.allCases, id: \.self) { value in
                    Button {
                        model.dnsRequiredProtocol = value
                    } label: {
                        Text(protocolTitle(value))
                            .guardFont(size: 12, weight: .semibold)
                            .foregroundStyle(model.dnsRequiredProtocol == value
                                ? MenuPalette.accentText : SettingsPalette.muted)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 9)
                            .background(
                                model.dnsRequiredProtocol == value
                                    ? SettingsPalette.accentFill
                                    : SettingsPalette.card,
                                in: RoundedRectangle(cornerRadius: 8, style: .continuous)
                            )
                            .overlay {
                                RoundedRectangle(cornerRadius: 8, style: .continuous)
                                    .stroke(model.dnsRequiredProtocol == value
                                        ? SettingsPalette.accentFill
                                        : SettingsPalette.line, lineWidth: 1)
                            }
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(protocolTitle(value))
                    .accessibilityValue(model.dnsRequiredProtocol == value ? "已锁定" : "未选择")
                    .accessibilityAddTraits(model.dnsRequiredProtocol == value ? .isSelected : [])
                }
            }
            Text("选择后点击下方“保存网络设置”。DoH 与 DoT 均使用加密传输；只允许你选定的协议。")
                .guardFont(size: 11)
                .foregroundStyle(SettingsPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 13)
    }

    private func protocolTitle(_ value: DNSRequiredProtocol) -> String {
        switch value {
        case .anyEncrypted: return "DoH 或 DoT"
        case .dnsOverHTTPS: return "仅 DoH"
        case .dnsOverTLS: return "仅 DoT"
        }
    }

    private var dnsProxyControl: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(SettingsPalette.accent)
                    .frame(width: 38, height: 38)
                    .background(SettingsPalette.row, in: RoundedRectangle(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 5) {
                    Text("Claude DNS flow 监测")
                        .guardFont(size: 15, weight: .bold)
                        .foregroundStyle(SettingsPalette.text)
                    Text(dnsStatusDescription)
                        .guardFont(size: 12)
                        .foregroundStyle(SettingsPalette.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                dnsStatusMark
            }

            HStack {
                Label(dnsStatusTitle, systemImage: dnsStatusSymbol)
                    .guardFont(size: 12, weight: .semibold)
                    .foregroundStyle(dnsStatusColor)
                Spacer()
                if isDNSOperationPending {
                    ProgressView().controlSize(.small)
                } else if dnsEnrollment.state == .active {
                    Button("停用监测") { dnsAction = .disable }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(ifUnsupportedSystem)
                } else {
                    Button("启用监测") { dnsAction = .enable }
                        .buttonStyle(AccentButtonStyle())
                    .disabled(ifUnsupportedSystem)
                }
            }
            .padding(12)
            .background(SettingsPalette.row, in: RoundedRectangle(cornerRadius: 10))

            if case .failed(let message) = dnsEnrollment.state {
                Label(message, systemImage: "exclamationmark.triangle")
                    .guardFont(size: 12, weight: .medium)
                    .foregroundStyle(SettingsPalette.danger)
                    .fixedSize(horizontal: false, vertical: true)
            }
                Text(ifUnsupportedSystem
                 ? "DNS Proxy 扩展需要 macOS 15 或更新版本。其他检查仍可使用；D01–D04 会保持未知并阻断。"
                 : "DNS flow 只在本机转发。查询名不会保存；短期记录只含域名类别、传输类型、进程身份、解析器摘要、可选国家码和适用的加密协议类别。启用 IPWho 后，D02/D03 对 port 53、标准 DoT 和明确配置的 DoH endpoint 发送固定 whoami TXT 查询，再把递归出口 IP 发送至 IPWho；短期证据不含 IP 或 DoH URL。D01 比较实际解析器与系统配置；D04 检查目标域名当前生效的 DoH/DoT 设置及会话内降级。首次观测、明文设置或路由歧义会阻断。")
                .guardFont(size: 11)
                .foregroundStyle(SettingsPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .contain)
    }

    private var isDNSOperationPending: Bool {
        dnsEnrollment.state == .requestingExtensionApproval ||
            dnsEnrollment.state == .configuringDNSProxy
    }

    private var ifUnsupportedSystem: Bool {
        ProcessInfo.processInfo.operatingSystemVersion.majorVersion < 15
    }

    private var dnsStatusTitle: String {
        switch dnsEnrollment.state {
        case .inactive: return "未启用"
        case .requestingExtensionApproval: return "等待 macOS 批准"
        case .configuringDNSProxy: return "正在配置 DNS Proxy"
        case .active: return "已启用"
        case .failed: return "操作失败"
        }
    }

    private var dnsStatusDescription: String {
        switch dnsEnrollment.state {
        case .inactive: return "观察 Claude 实际使用的 DNS 解析器路径。"
        case .requestingExtensionApproval: return "请完成 macOS 显示的 System Extension 授权。"
        case .configuringDNSProxy: return "正在保存系统 DNS Proxy 设置。"
        case .active: return "系统 DNS Proxy 已启用；目标 flow 的进程身份与解析策略将用于启动和运行中复核。"
        case .failed: return "扩展或系统 DNS Proxy 配置未能完成。"
        }
    }

    private var dnsStatusSymbol: String {
        switch dnsEnrollment.state {
        case .inactive: return "minus.circle"
        case .requestingExtensionApproval, .configuringDNSProxy: return "clock"
        case .active: return "checkmark.circle"
        case .failed: return "xmark.circle"
        }
    }

    private var dnsStatusColor: Color {
        switch dnsEnrollment.state {
        case .inactive: return SettingsPalette.muted
        case .requestingExtensionApproval, .configuringDNSProxy: return MenuPalette.amber
        case .active: return SettingsPalette.success
        case .failed: return SettingsPalette.danger
        }
    }

    @ViewBuilder
    private var dnsStatusMark: some View {
        switch dnsEnrollment.state {
        case .inactive:
            Image(systemName: "pause.circle.fill").foregroundStyle(SettingsPalette.muted)
        case .requestingExtensionApproval, .configuringDNSProxy:
            Image(systemName: "clock.fill").foregroundStyle(MenuPalette.amber)
        case .active:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(SettingsPalette.success)
        case .failed:
            Image(systemName: "xmark.circle.fill").foregroundStyle(SettingsPalette.danger)
        }
    }
}

struct LocalDataSettingsPage: View {
    @ObservedObject var model: SettingsModel
    let clearHistory: () -> Void
    let exportDiagnostics: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 17) {
            Rectangle().fill(SettingsPalette.line).frame(height: 1)
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("环境状态通知")
                            .guardFont(size: 15, weight: .bold)
                            .foregroundStyle(SettingsPalette.text)
                        Text("风险出现时提醒一次，环境恢复后再提醒一次。")
                            .guardFont(size: 12)
                            .foregroundStyle(SettingsPalette.muted)
                    }
                    Spacer(minLength: 10)
                    Toggle("桌面状态通知", isOn: Binding(
                        get: { model.notificationsEnabled },
                        set: { enabled in
                            Task { await model.setNotificationsEnabled(enabled) }
                        }
                    ))
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .tint(SettingsPalette.accent)
                    .accessibilityLabel("桌面状态通知")
                    .accessibilityValue(model.notificationsEnabled ? "已开启" : "已关闭")
                }
                Text("首次开启时由 macOS 请求通知权限。通知不包含 IP、配置路径或会话内容；持续状态只提醒一次。")
                    .guardFont(size: 12)
                    .foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            SettingsDivider()
            VStack(alignment: .leading, spacing: 8) {
                Label("IP 地址信誉 · ipapi.is", systemImage: "shield.lefthalf.filled")
                    .guardFont(size: 15, weight: .bold)
                    .foregroundStyle(SettingsPalette.text)
                Text("保存 API key 后，SafeClaude 会把 Claude API 出口 IP 发送至 ipapi.is，检查近期滥用记录和已知开放代理。结果按出口与路由缓存 6 小时；密钥存于 macOS 钥匙串。")
                    .guardFont(size: 13)
                    .foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
                Text("该服务的 API key 也可访问账户管理接口。建议为 SafeClaude 使用专用 key；停用后可在这里移除。")
                    .guardFont(size: 12, weight: .medium)
                    .foregroundStyle(SettingsPalette.danger)
                    .fixedSize(horizontal: false, vertical: true)
                SecureField("粘贴 ipapi.is API key", text: $model.ipAPIKey)
                    .guardInput()
                HStack {
                    Button("保存到钥匙串", action: model.saveIPAPIKey)
                        .buttonStyle(AccentButtonStyle())
                        .disabled(model.ipAPIKey.isEmpty)
                    Button("移除 API key", action: model.removeIPAPIKey)
                        .buttonStyle(SecondaryButtonStyle())
                }
                .padding(.top, 3)
            }
            SettingsDivider()
            VStack(alignment: .leading, spacing: 8) {
                Label("ProxyCheck 信誉查询", systemImage: "key.horizontal")
                    .guardFont(size: 15, weight: .bold)
                    .foregroundStyle(SettingsPalette.text)
                Text("仅在“网络与隐私”中开启 ProxyCheck 查询后发送出口 IP。无需 API key 即可使用免费额度；可选 API key 保存在 macOS 钥匙串并提高额度。")
                    .guardFont(size: 13)
                    .foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
                SecureField("粘贴 ProxyCheck API key", text: $model.providerKey)
                    .guardInput()
                HStack {
                    Button("保存到钥匙串", action: model.saveKey)
                        .buttonStyle(AccentButtonStyle())
                        .disabled(model.providerKey.isEmpty)
                    Button("移除 API key", action: model.removeKey)
                        .buttonStyle(SecondaryButtonStyle())
                }
                .padding(.top, 3)
            }
            SettingsDivider()
            VStack(alignment: .leading, spacing: 8) {
                Label("本机网络历史", systemImage: "clock.arrow.circlepath")
                    .guardFont(size: 15, weight: .bold)
                    .foregroundStyle(SettingsPalette.text)
                Text("历史样本最多保留 24 小时，并受容量上限约束。原始 IP 不落盘；出口地址与环境上下文以 Keychain 密钥计算 HMAC 摘要。")
                    .guardFont(size: 13)
                    .foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
                Text("国家码、ASN、采样时间和风险标记以明文存于仅当前用户可读写的文件（权限 0600）中，文件未整体加密；可随时清除。")
                    .guardFont(size: 12)
                    .foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
                Button("清除网络历史", role: .destructive, action: clearHistory)
                    .buttonStyle(SecondaryButtonStyle())
                    .padding(.top, 2)
            }
            SettingsDivider()
            VStack(alignment: .leading, spacing: 8) {
                Label("脱敏诊断文件", systemImage: "doc.text.magnifyingglass")
                    .guardFont(size: 15, weight: .bold)
                    .foregroundStyle(SettingsPalette.text)
                Text("导出当前检查分数、状态和规则编号，供本地排查或主动分享。文件不含原因原文、IP、代理配置、会话标识、票据或本地路径。")
                    .guardFont(size: 13)
                    .foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
                Button("导出脱敏诊断", action: exportDiagnostics)
                    .buttonStyle(SecondaryButtonStyle())
                    .padding(.top, 2)
            }
            SettingsDivider()
            VStack(alignment: .leading, spacing: 6) {
                Label("本机数据边界", systemImage: "lock.shield")
                    .guardFont(size: 15, weight: .bold)
                    .foregroundStyle(SettingsPalette.text)
                Text("环境检查不读取 Claude 登录凭据、对话正文或项目源码。诊断状态保存在本机。")
                    .guardFont(size: 13)
                    .foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Rectangle().fill(SettingsPalette.line).frame(height: 1)
        }
        .padding(.vertical, 8)
    }
}

struct SettingsDivider: View {
    var body: some View {
        Rectangle().fill(SettingsPalette.line).frame(height: 1).padding(.vertical, 15)
    }
}

struct ThresholdSettingRow: View {
    let title: String
    let detail: String
    @Binding var value: Int

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 5) {
                Text(title).guardFont(size: 14, weight: .semibold).foregroundStyle(SettingsPalette.text)
                Text(detail).guardFont(size: 12).foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            HStack(spacing: 8) {
                Button { value = max(0, value - 1) } label: {
                    Image(systemName: "minus").frame(width: 26, height: 26)
                }
                .buttonStyle(StepperButtonStyle())
                .accessibilityLabel("降低\(title)")
                .accessibilityValue("\(value)")
                .help("降低\(title)")
                Text("\(value)")
                    .guardFont(size: 19, weight: .bold, design: .rounded)
                    .monospacedDigit()
                    .foregroundStyle(SettingsPalette.text)
                    .frame(width: 30)
                    .accessibilityLabel("\(title)，当前 \(value) 分")
                Button { value = min(100, value + 1) } label: {
                    Image(systemName: "plus").frame(width: 26, height: 26)
                }
                .buttonStyle(StepperButtonStyle())
                .accessibilityLabel("提高\(title)")
                .accessibilityValue("\(value)")
                .help("提高\(title)")
            }
        }
    }
}

struct ToggleSettingRow: View {
    let title: String
    let detail: String
    @Binding var value: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            VStack(alignment: .leading, spacing: 5) {
                Text(title).guardFont(size: 14, weight: .semibold).foregroundStyle(SettingsPalette.text)
                Text(detail).guardFont(size: 12).foregroundStyle(SettingsPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            Toggle(title, isOn: $value)
                .labelsHidden()
                .tint(SettingsPalette.accent)
                .accessibilityLabel(title)
        }
    }
}
