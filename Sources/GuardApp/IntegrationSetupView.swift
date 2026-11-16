import SwiftUI

struct IntegrationSetupView: View {
    @ObservedObject var model: IntegrationSetupModel
    let onIntegrationChanged: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var confirmingInstall = false
    @State private var confirmingUpgrade = false
    @State private var confirmingUninstall = false

    private var stateColor: Color {
        if model.isBusy { return MenuPalette.amber }
        if model.statusIsError { return MenuPalette.coral }
        return model.isIntegrated ? MenuPalette.accentInk : MenuPalette.amber
    }

    private var statusTitle: String {
        model.isIntegrated ? "本机启动集成已登记" : "尚未安装启动集成"
    }

    private var statusDescription: String {
        model.isIntegrated
            ? "终端 shim、官方 processWrapper 和后台服务由同一份本机安装清单管理。"
            : "首次安装会把运行组件复制到用户级目录，并登记用户后台服务。"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            ScrollView {
                VStack(alignment: .leading, spacing: 23) {
                    statusLine
                    claudePicker
                    if !model.isIntegrated {
                        integrationOptions
                    } else {
                        installedSummary
                    }
                    requirements
                    if !model.statusMessage.isEmpty {
                        Label(model.statusMessage,
                              systemImage: model.statusIsError ? "exclamationmark.triangle.fill" :
                                (model.isBusy ? "arrow.triangle.2.circlepath" : "info.circle"))
                            .guardFont(size: 12, weight: .medium)
                            .foregroundStyle(model.statusIsError ? MenuPalette.coral : MenuPalette.muted)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.leading, 13)
                            .padding(.vertical, 10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(alignment: .leading) {
                                Capsule()
                                    .fill(model.statusIsError ? MenuPalette.coral : MenuPalette.accentInk)
                                    .frame(width: 3)
                                    .padding(.vertical, 5)
                            }
                    }
                }
                .padding(.horizontal, 30)
                .padding(.vertical, 25)
            }
            footer
        }
        .frame(minWidth: 700, idealWidth: 740, minHeight: 590, idealHeight: 620)
        .background(MenuPalette.canvas)
        .onAppear { model.refresh() }
        .onChange(of: model.isIntegrated) { _ in
            onIntegrationChanged()
        }
        .confirmationDialog("启用 Claude Code 启动保护？", isPresented: $confirmingInstall,
                            titleVisibility: .visible) {
            Button("安装并接入", action: model.install)
            Button("取消", role: .cancel) {}
        } message: {
            Text(installConfirmation)
        }
        .confirmationDialog("升级 SafeClaude 集成？", isPresented: $confirmingUpgrade,
                            titleVisibility: .visible) {
            Button("升级", action: model.upgrade)
            Button("取消", role: .cancel) {}
        } message: {
            Text("将检查当前安装清单，保留现有 shell、Claude 设置和 LaunchAgent；如检测到编辑或活动受管会话，升级会停止并保留现状。")
        }
        .confirmationDialog("完整移除 SafeClaude？", isPresented: $confirmingUninstall,
                            titleVisibility: .visible) {
            Button("移除 SafeClaude 集成", role: .destructive, action: model.uninstall)
                .disabled(!model.canUninstall)
            Button("取消", role: .cancel) {}
        } message: {
            Text("先暂停新的受管启动并确认没有活动会话，再撤销 SafeClaude DNS System Extension 与特权校时服务，随后安全移除校时状态快照，并移除 SafeClaude 添加的 shell 入口、Claude processWrapper/hook、用户后台服务和安装组件。Claude Code 程序与其他配置会保留。若 macOS 要求重启、权限不足或发现配置被修改，卸载会停止并保留可恢复的安装组件。")
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 21, weight: .semibold))
                .foregroundStyle(MenuPalette.accentText)
                .frame(width: 46, height: 46)
                .background(MenuPalette.accent, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text(model.isIntegrated ? "Claude Code 已接入" : "先接入，再启动")
                    .guardFont(size: 24, weight: .bold)
                    .tracking(-0.45)
                    .foregroundStyle(MenuPalette.ink)
                Text(model.isIntegrated
                     ? "SafeClaude 将在每次受保护启动前重新检查当前环境。"
                     : "把 Claude Code 的启动入口连接到本机评分与阻断服务。")
                    .guardFont(size: 13)
                    .foregroundStyle(MenuPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            Button {
                model.refresh()
            } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(MenuPalette.ink)
                    .frame(width: 34, height: 34)
                    .background(MenuPalette.surface, in: Circle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("重新检查集成状态")
        }
        .padding(.horizontal, 30)
        .padding(.top, 27)
        .padding(.bottom, 23)
        .overlay(alignment: .bottom) {
            Rectangle().fill(MenuPalette.line).frame(height: 1)
        }
    }

    private var statusLine: some View {
        HStack(alignment: .top, spacing: 12) {
            Circle()
                .fill(stateColor)
                .frame(width: 9, height: 9)
                .padding(.top, 5)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(statusTitle)
                    .guardFont(size: 14, weight: .semibold)
                    .foregroundStyle(MenuPalette.ink)
                Text(statusDescription)
                    .guardFont(size: 12)
                    .foregroundStyle(MenuPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if model.isBusy { ProgressView().controlSize(.small) }
        }
        .padding(.vertical, 16)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(statusTitle)
        .accessibilityValue(Text(
            "\(statusDescription)\(model.isBusy ? " 当前正在处理。" : "")"
        ))
    }

    private var claudePicker: some View {
        VStack(alignment: .leading, spacing: 10) {
            setupSectionHeading(number: "01", title: "选择 Claude Code")
            HStack(spacing: 10) {
                TextField("选择 Claude Code 文件", text: $model.claudeExecutable)
                    .font(.system(size: 12, design: .monospaced))
                    .guardInput()
                    .accessibilityLabel("Claude Code 可执行文件路径")
                Button("选择文件", action: model.chooseClaudeExecutable)
                    .buttonStyle(SecondaryButtonStyle())
                    .disabled(model.isBusy)
            }
            Text("SafeClaude 只读取并校验目标版本与文件身份，不会替换这个文件。")
                .guardFont(size: 11)
                .foregroundStyle(MenuPalette.muted)
        }
        .padding(.vertical, 16)
        .overlay(alignment: .bottom) {
            Rectangle().fill(MenuPalette.line).frame(height: 1)
        }
    }

    private var integrationOptions: some View {
        VStack(alignment: .leading, spacing: 13) {
            setupSectionHeading(number: "02", title: "选择启动入口")
            option(
                title: "终端命令",
                detail: "在 ~/.zshrc 添加 SafeClaude PATH shim，让终端与继承 PATH 的自动化先经过启动检查。",
                isOn: $model.addShellIntegration
            )
            Rectangle().fill(MenuPalette.line).frame(height: 1)
            option(
                title: "Claude 官方 processWrapper",
                detail: "在 Claude settings 中合并官方包装入口与失败事件 hook，覆盖 Claude Code 后续 self-spawn。",
                isOn: $model.addClaudeSettingsIntegration
            )
        }
        .padding(.vertical, 16)
        .overlay(alignment: .bottom) {
            Rectangle().fill(MenuPalette.line).frame(height: 1)
        }
    }

    private func option(title: String, detail: String, isOn: Binding<Bool>) -> some View {
        HStack(alignment: .top, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .guardFont(size: 13, weight: .semibold)
                    .foregroundStyle(MenuPalette.ink)
                Text(detail)
                    .guardFont(size: 11)
                    .foregroundStyle(MenuPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Toggle(title, isOn: isOn)
                .labelsHidden()
                .tint(MenuPalette.accent)
                .accessibilityLabel(title)
        }
        .disabled(model.isBusy)
    }

    private var installedSummary: some View {
        VStack(alignment: .leading, spacing: 10) {
            setupSectionHeading(number: "02", title: "管理现有安装")
            Text("升级会沿用已登记的集成范围，并保留 Claude 设置中的其他字段。")
                .guardFont(size: 12)
                .foregroundStyle(MenuPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
            Label("卸载前会检查受管会话并撤销系统级扩展与后台服务；任何一步未确认完成时都会保留安装组件。",
                  systemImage: "arrow.uturn.backward.circle")
                .guardFont(size: 11)
                .foregroundStyle(MenuPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) {
            Rectangle().fill(MenuPalette.line).frame(height: 1)
        }
    }

    private var requirements: some View {
        VStack(alignment: .leading, spacing: 7) {
            setupSectionHeading(number: "03", title: "启用前检查")
            requirement("安装前先将 App 放在 /Applications", satisfied: model.appCanInstall)
            requirement("SafeClaude 安装组件完整", satisfied: model.installerAvailable)
            requirement("已选择可执行的 Claude Code 文件", satisfied: model.hasValidClaudeExecutable)
            requirement("至少启用一种启动入口", satisfied: model.hasEnabledEntryPoint || model.isIntegrated)
        }
    }

    private func requirement(_ title: String, satisfied: Bool) -> some View {
        Label(title, systemImage: satisfied ? "checkmark.circle.fill" : "circle")
            .guardFont(size: 11, weight: .medium)
            .foregroundStyle(satisfied ? MenuPalette.accentInk : MenuPalette.muted)
    }

    private func setupSectionHeading(number: String, title: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(number)
                .guardFont(size: 11, weight: .bold, design: .monospaced)
                .foregroundStyle(MenuPalette.accentInk)
            Text(title)
                .guardFont(size: 14, weight: .semibold)
                .foregroundStyle(MenuPalette.ink)
        }
    }

    private var footer: some View {
        HStack(spacing: 12) {
            Text("安全分越高越安全。信息未齐全或低于门槛时，启动会被阻断。")
                .guardFont(size: 11)
                .foregroundStyle(MenuPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Button("关闭") { dismiss() }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(model.isBusy)
            if model.isIntegrated {
                Button(model.isBusy ? "正在升级" : "检查并升级", action: { confirmingUpgrade = true })
                    .buttonStyle(AccentButtonStyle())
                    .disabled(!model.canUpgrade)
                Button("卸载", role: .destructive) { confirmingUninstall = true }
                    .buttonStyle(DestructiveButtonStyle())
                    .disabled(!model.canUninstall)
                    .accessibilityHint("暂停新会话后撤销 SafeClaude 系统服务并移除本机集成")
            } else {
                Button(model.isBusy ? "正在安装" : "接入 Claude", action: { confirmingInstall = true })
                    .buttonStyle(AccentButtonStyle())
                    .disabled(!model.canInstall)
            }
        }
        .padding(.horizontal, 30)
        .padding(.vertical, 16)
        .overlay(alignment: .top) {
            Rectangle().fill(MenuPalette.line).frame(height: 1)
        }
    }

    private var installConfirmation: String {
        var changes: [String] = ["复制本机运行组件", "登记 SafeClaude 用户后台服务"]
        if model.addShellIntegration { changes.append("在 ~/.zshrc 添加 PATH shim") }
        if model.addClaudeSettingsIntegration {
            changes.append("合并 Claude processWrapper 与 StopFailure hook")
        }
        return "即将执行：\(changes.joined(separator: "；"))。现有配置会先检查再合并；遇到冲突或活动受管会话时会停止并保留现状。"
    }
}
