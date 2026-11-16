import SwiftUI
import GuardCore

struct MenuView: View {
    @ObservedObject var model: MenuModel
    @ObservedObject var integrationModel: IntegrationSetupModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    private var response: GuardResponse? { model.response }
    private var score: Int? { response?.safetyScore }
    private var title: String {
        guard let response else {
            if model.stale { return "状态需要刷新" }
            return model.checking ? "正在读取环境" : "后台暂不可达"
        }
        if response.assessmentContext == .claudeLaunch {
            switch response.decision {
            case "allow": return "最近启动检查通过"
            case "warning": return "最近启动建议复核"
            case "deny": return "最近启动已拦截"
            default: return "最近启动暂不放行"
            }
        }
        if response.assessmentContext == .managedSession {
            return response.decision == "deny" || response.decision == "hold"
                ? "受管会话正在处置" : "受管会话检查通过"
        }
        switch response.decision {
        case "allow": return "环境状态稳定"
        case "warning": return "可以启动，建议复核"
        case "deny": return "启动保护已拦截"
        default: return "检查尚未完成"
        }
    }
    private var scoreText: String {
        guard let response else { return "—" }
        if let score = response.safetyScore { return "\(score)" }
        return "—"
    }
    private var statusColor: Color {
        guard let decision = response?.decision else { return MenuPalette.amber }
        switch decision {
        case "allow": return MenuPalette.accentInk
        case "warning", "hold": return MenuPalette.amber
        default: return MenuPalette.coral
        }
    }
    private var connectionLabel: String {
        if !integrationModel.isIntegrated { return "未接入" }
        if model.checking && response == nil { return "检查中" }
        if model.stale { return "状态过期" }
        guard let response else { return "后台离线" }
        if response.assessmentContext == .claudeLaunch { return "最近启动" }
        if response.assessmentContext == .managedSession { return "受管会话" }
        return response.decision == "deny" || response.decision == "hold" ? "保护中" : "持续监测"
    }
    private var accessibleScore: String {
        guard let response else { return "环境安全分暂不可用，\(title)" }
        if let score = response.safetyScore { return "环境安全分 \(score) 分，\(title)" }
        return "环境安全分未知，上限 \(response.scoreUpperBound ?? 0) 分，\(title)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            MenuMasthead(connectionLabel: connectionLabel,
                         statusColor: statusColor,
                         isChecking: model.checking)
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 22) {
                    if !integrationModel.isIntegrated {
                        MenuSetupPrompt(openSetup: { openWindow(id: "integration") })
                    }
                    MenuScorePanel(
                        score: score,
                        upperBound: response?.scoreUpperBound,
                        scoreText: scoreText,
                        title: title,
                        decision: response?.decision,
                        thresholdText: response.map(thresholdLabel),
                        thresholdDetail: response.map(thresholdDetail),
                        isChecking: model.checking,
                        checkedAt: response?.checkedAt,
                        accessibleLabel: accessibleScore
                    )
                    if let response {
                        MenuFindingSection(response: response)
                        MenuCoverageSection(response: response)
                    } else {
                        MenuOfflineSection(isChecking: model.checking,
                                           isStale: model.stale,
                                           reconnect: model.refresh)
                    }
                }
                .padding(.horizontal, 22)
                .padding(.top, 20)
                .padding(.bottom, 18)
            }
            MenuDashboardFooter(isChecking: model.checking,
                                refresh: model.refresh,
                                openSettings: { openWindow(id: "settings") },
                                openReport: { openWindow(id: "report") },
                                openIntegration: { openWindow(id: "integration") })
        }
        .frame(width: dynamicTypeSize.isAccessibilitySize ? 460 : 420,
               height: dynamicTypeSize.isAccessibilitySize ? 760 : 650)
        .background(MenuPalette.canvas)
        .task {
            integrationModel.refresh()
            await monitorStatus()
        }
        .animation(reduceMotion ? nil : .easeOut(duration: 0.25), value: score)
    }

    private func thresholdLabel(for response: GuardResponse) -> String {
        let threshold = response.assessmentContext == .managedSession
            ? model.runtimeMinimumScore : model.minimumScore
        guard let threshold else { return "策略门槛暂不可读取" }
        switch response.decision {
        case "deny": return "低于最低安全分 \(threshold)，已拦截"
        case "hold": return "信息不足，暂不放行"
        case "warning": return "已达到门槛 \(threshold)，建议复核"
        default:
            if response.assessmentContext == .managedSession {
                return "受管会话运行门槛 \(threshold)"
            }
            return "Claude 启动门槛 \(threshold)"
        }
    }

    private func thresholdDetail(for response: GuardResponse) -> String {
        if response.decision == "hold" {
            return "必要检查完成前不会启动 Claude"
        }
        if response.assessmentContext == .managedSession {
            return response.decision == "deny"
                ? "受管会话按运行中策略处置"
                : "低于运行中门槛时会结束受管会话"
        }
        return response.decision == "deny"
            ? "修复触发项后重新检测"
            : "低于启动门槛会阻止新会话"
    }

    private func monitorStatus() async {
        model.refresh()
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(12))
            guard !Task.isCancelled else { return }
            model.refresh()
        }
    }
}
