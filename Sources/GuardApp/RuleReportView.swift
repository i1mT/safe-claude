import SwiftUI
import GuardCore

private enum ReportRuleState {
    case triggered(Int)
    case triggeredIncomplete(Int)
    case passed
    case notApplicable
    case unknown
    case unsupported
    case missing
    case unreported

    var title: String {
        switch self {
        case .triggered: return "已触发"
        case .triggeredIncomplete: return "已触发 · 待补全"
        case .passed: return "已通过"
        case .notApplicable: return "不适用"
        case .unknown: return "待确认"
        case .unsupported: return "暂不支持"
        case .missing: return "缺少观测"
        case .unreported: return "未报告"
        }
    }

    var color: Color {
        switch self {
        case .triggered, .triggeredIncomplete: return MenuPalette.coral
        case .passed: return MenuPalette.accentInk
        case .notApplicable: return MenuPalette.muted
        case .unknown: return MenuPalette.amber
        case .unsupported, .missing: return MenuPalette.amber
        case .unreported: return MenuPalette.muted
        }
    }

    var guidanceTitle: String {
        switch self {
        case .triggered: return "建议处理"
        case .triggeredIncomplete: return "风险已发现，补齐检查"
        case .unknown: return "补齐检查"
        case .unsupported: return "当前适配范围"
        case .missing: return "恢复观测"
        case .passed: return "保持当前状态"
        case .notApplicable: return "适用条件"
        case .unreported: return "检查状态"
        }
    }

    var deductionPoints: Int? {
        switch self {
        case .triggered(let points), .triggeredIncomplete(let points): return points
        default: return nil
        }
    }
}

private struct ReportRule: Identifiable {
    let id: String
    let state: ReportRuleState
    let source: String?
    let observedAt: Date?
    let remediation: String?
}

struct RuleReportView: View {
    let response: GuardResponse?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var selectedGroup = "全部"
    @State private var expandedRules = Set<String>()

    private var rules: [ReportRule] {
        if let statuses = response?.ruleStatuses {
            let byID = Dictionary(statuses.map { ($0.rule, $0) },
                                  uniquingKeysWith: { first, _ in first })
            return SafetyRuleCatalog.ids.map { id in
                guard let item = byID[id] else {
                    return ReportRule(id: id, state: .unreported, source: nil, observedAt: nil,
                                      remediation: RuleLabels.remediation[id])
                }
                let state: ReportRuleState
                switch item.status {
                case "triggered": state = .triggered(item.points)
                case "triggeredUnknown": state = .triggeredIncomplete(item.points)
                case "passed": state = .passed
                case "notApplicable": state = .notApplicable
                case "unknown": state = .unknown
                case "unsupported": state = .unsupported
                case "missing": state = .missing
                default: state = .unreported
                }
                return ReportRule(
                    id: id, state: state, source: item.source, observedAt: item.observedAt,
                    remediation: item.remediation ?? RuleLabels.remediation[id]
                )
            }
        }
        let triggered = Dictionary(response?.findings.map { ($0.rule, $0.points) } ?? [],
                                  uniquingKeysWith: { first, _ in first })
        let unknown = Set(response?.unknownRules ?? [])
        return SafetyRuleCatalog.ids.map { id in
            if let points = triggered[id] {
                return ReportRule(id: id, state: .triggered(points), source: nil, observedAt: nil,
                                  remediation: RuleLabels.remediation[id])
            }
            if unknown.contains(id) {
                return ReportRule(id: id, state: .unknown, source: nil, observedAt: nil,
                                  remediation: RuleLabels.remediation[id])
            }
            return ReportRule(id: id, state: .unreported, source: nil, observedAt: nil,
                              remediation: RuleLabels.remediation[id])
        }
    }

    private var visibleRules: [ReportRule] {
        guard selectedGroup != "全部" else { return rules }
        return rules.filter { $0.id.hasPrefix(selectedGroup) }
    }

    private var reportedCount: Int {
        rules.filter {
            if case .unreported = $0.state { return false }
            return true
        }.count
    }

    private var riskCount: Int {
        rules.filter {
            switch $0.state {
            case .triggered, .triggeredIncomplete: return true
            default: return false
            }
        }.count
    }

    private var pendingCount: Int {
        rules.filter {
            switch $0.state {
            case .triggeredIncomplete, .unknown, .unsupported, .missing, .unreported: return true
            default: return false
            }
        }.count
    }

    private var passedCount: Int {
        rules.filter {
            if case .passed = $0.state { return true }
            return false
        }.count
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            HStack(alignment: .bottom, spacing: 18) {
                ForEach(["全部", "A", "B", "C", "D", "E", "F", "G", "H"], id: \.self) { group in
                    Button {
                        selectedGroup = group
                    } label: {
                        VStack(spacing: 7) {
                            Text(group)
                                .guardFont(size: 12, weight: .bold,
                                           design: group == "全部" ? .default : .monospaced)
                                .foregroundStyle(selectedGroup == group
                                    ? MenuPalette.ink : MenuPalette.muted)
                            Rectangle()
                                .fill(selectedGroup == group ? MenuPalette.accentInk : .clear)
                                .frame(height: 2)
                        }
                        .fixedSize(horizontal: true, vertical: false)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(group == "全部" ? "全部检查项目" : "\(group) 类检查项目")
                    .accessibilityAddTraits(selectedGroup == group ? .isSelected : [])
                    .help(group == "全部" ? "显示全部检查项目" : "只显示 \(group) 类检查项目")
                }
                Spacer()
            }
            .padding(.horizontal, 24)
            .padding(.top, 11)
            .overlay(alignment: .bottom) {
                Rectangle().fill(MenuPalette.line).frame(height: 1)
            }

            ScrollView {
                LazyVStack(spacing: 1) {
                    ForEach(visibleRules) { rule in
                        ruleRow(rule)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 24)
            }
        }
        .frame(minWidth: 720, minHeight: 580)
        .background(MenuPalette.canvas)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("64 项检查")
                        .guardFont(size: 11, weight: .bold, design: .monospaced)
                        .foregroundStyle(MenuPalette.accentInk)
                    Text("环境检查")
                        .guardFont(size: 23, weight: .bold)
                        .foregroundStyle(MenuPalette.ink)
                }
                Spacer()
                Text("\(reportedCount) / 64 已报告")
                    .guardFont(size: 12, weight: .semibold, design: .rounded)
                    .foregroundStyle(MenuPalette.ink)
                    .monospacedDigit()
            }
            Text("逐项显示评分器本次收到的检查状态。缺少观测、未知和暂不支持都会单独标出；后台没有返回的规则显示为未报告，不代表检查通过。")
                .guardFont(size: 13)
                .foregroundStyle(MenuPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
            if let response {
                Text("\(contextTitle(response.assessmentContext)) · \(response.checkedAt.formatted(date: .abbreviated, time: .standard))")
                    .guardFont(size: 11, weight: .medium, design: .monospaced)
                    .foregroundStyle(MenuPalette.muted)
            } else {
                Text("后台不可达，当前没有可展示的检查结果。")
                    .guardFont(size: 11, weight: .semibold)
                    .foregroundStyle(MenuPalette.amber)
            }
            HStack(spacing: 0) {
                ReportSummaryMetric(value: riskCount, label: "风险项", tint: MenuPalette.coral)
                reportSummaryDivider
                ReportSummaryMetric(value: pendingCount, label: "待确认", tint: MenuPalette.amber)
                reportSummaryDivider
                ReportSummaryMetric(value: passedCount, label: "已通过", tint: MenuPalette.accentInk)
                reportSummaryDivider
                ReportSummaryMetric(value: reportedCount, label: "已报告 / 64", tint: MenuPalette.ink)
            }
            .padding(.top, 7)
        }
        .padding(24)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) { Rectangle().fill(MenuPalette.line).frame(height: 1) }
    }

    private var reportSummaryDivider: some View {
        Rectangle().fill(MenuPalette.line).frame(width: 1, height: 34)
    }

    private func ruleRow(_ rule: ReportRule) -> some View {
        let isExpanded = expandedRules.contains(rule.id)
        return VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.16)) {
                    if isExpanded { expandedRules.remove(rule.id) }
                    else { expandedRules.insert(rule.id) }
                }
            } label: {
                HStack(spacing: 12) {
                    Text(rule.id)
                        .guardFont(size: 11, weight: .bold, design: .monospaced)
                        .foregroundStyle(MenuPalette.accentInk)
                        .frame(width: 42, alignment: .leading)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(RuleLabels.chinese[rule.id] ?? "规则说明待补充")
                            .guardFont(size: 13, weight: .medium)
                            .foregroundStyle(MenuPalette.ink)
                            .multilineTextAlignment(.leading)
                        if let source = rule.source {
                            Text("来源 · \(sourceTitle(source))")
                                .guardFont(size: 11, weight: .medium)
                                .foregroundStyle(MenuPalette.muted)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    if let points = rule.state.deductionPoints {
                        Text("−\(points)")
                            .guardFont(size: 11, weight: .bold, design: .monospaced)
                            .foregroundStyle(MenuPalette.coral)
                    }
                    Text(rule.state.title)
                            .guardFont(size: 11, weight: .semibold)
                        .foregroundStyle(rule.state.color)
                        .fixedSize()
                    Image(systemName: "chevron.down")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(MenuPalette.muted)
                        .rotationEffect(.degrees(isExpanded ? 180 : 0))
                        .frame(width: 14)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(ruleAccessibilityLabel(rule, expanded: isExpanded))
            .accessibilityHint(isExpanded ? "收起处理建议" : "展开处理建议")

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    Text(rule.state.guidanceTitle)
                        .guardFont(size: 11, weight: .bold)
                        .foregroundStyle(rule.state.color)
                    Text(rule.remediation ?? "查看规则状态并重新运行环境检查。")
                        .guardFont(size: 13)
                        .foregroundStyle(MenuPalette.ink.opacity(0.88))
                        .fixedSize(horizontal: false, vertical: true)
                    if let observedAt = rule.observedAt {
                        Label("最近采样 · \(observedAt.formatted(date: .abbreviated, time: .shortened))",
                              systemImage: "clock")
                            .guardFont(size: 11, weight: .medium, design: .monospaced)
                            .foregroundStyle(MenuPalette.muted)
                            .accessibilityLabel("最近采样时间，\(observedAt.formatted(date: .long, time: .shortened))")
                    } else {
                        Label("尚无可用采样时间", systemImage: "clock.badge.questionmark")
                            .guardFont(size: 11, weight: .medium)
                            .foregroundStyle(MenuPalette.amber)
                    }
                    if case .unknown = rule.state {
                        Text("证据补齐前，此项不会视为通过。")
                            .guardFont(size: 11, weight: .medium)
                            .foregroundStyle(MenuPalette.amber)
                    }
                    if case .triggeredIncomplete = rule.state {
                        Text("已计入已观测风险；剩余信号未观测，因此整体仍保持待确认。")
                            .guardFont(size: 11, weight: .medium)
                            .foregroundStyle(MenuPalette.amber)
                    }
                }
                .padding(.leading, 50)
                .padding(.top, 10)
                .accessibilityElement(children: .combine)
            }
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 12)
        .background(isExpanded ? MenuPalette.surface : .clear)
        .overlay(alignment: .bottom) {
            Rectangle().fill(MenuPalette.line.opacity(0.8)).frame(height: 1)
        }
    }

    private func ruleAccessibilityLabel(_ rule: ReportRule, expanded: Bool) -> String {
        let title = RuleLabels.chinese[rule.id] ?? "规则说明待补充"
        let points = rule.state.deductionPoints.map { "，扣除 \($0) 分" } ?? ""
        return "\(rule.id)，\(title)，\(rule.state.title)\(points)，\(expanded ? "已展开" : "已收起")"
    }

    private func sourceTitle(_ source: String) -> String {
        let labels = [
            "stale-snapshot": "环境快照过期",
            "reputation": "IP 信誉来源",
            "claude-settings-locale": "Claude 设置",
            "history": "本机历史",
            "proxy-sharing": "代理共享度数据",
            "region-policy": "地区策略",
            "reputation-location": "IP 地理位置来源",
            "country-languages": "国家语言目录",
            "region": "系统区域设置",
            "proxycheck": "ProxyCheck",
            "proxycheck-p2p-unobserved": "P2P 代理来源未接入",
            "ipapi-is": "ipapi.is",
            "ipapi-is-open-proxy-only": "ipapi.is 开放代理目录",
            "ipapi-is-unavailable": "ipapi.is 信誉查询不可用",
            "proxycheck-attack-history": "ProxyCheck 30 天攻击历史",
            "history-country-baseline": "国家历史基线",
            "history-country": "国家变化历史",
            "history-asn": "ASN 变化历史",
            "history-geolocation-window": "地理位置历史窗口",
            "geolocation-accuracy-unreported": "地理位置精度未提供",
            "https-clock-stale": "HTTPS 时间样本过期",
            "https-clock-boundary": "HTTPS 时间偏差边界",
            "target-route": "目标网络路径",
            "process-time-zone": "Claude 进程时区",
            "runtime-time-zone-inheritance": "运行环境时区继承",
            "process-locale": "Claude 进程语言环境",
            "claude-settings-language": "Claude 设置语言环境",
            "dns-path-unobserved": "Claude DNS 实际路径尚未观测",
            "dns-resolver-geolocation": "DNS 递归出口国家尚未确认",
            "dns-encryption-policy": "适用于目标域名的加密 DNS 策略尚未确认",
            "tls-options-unreadable": "Claude TLS 最低版本设置无法验证",
            "stun-country": "UDP/STUN 与 TCP 出口国家",
            "trust-config-unreadable": "CA 信任设置无法完整读取",
            "network-time-status-privileged": "自动网络校时状态需要特权读取",
            "runtime-virtualization": "虚拟化环境检测不可用",
            "client-certificate-unverified": "客户端证书设置无法验证",
        ]
        if let label = labels[source] { return label }
        if source.hasPrefix("collector-gap-"),
           SafetyRuleCatalog.weights[String(source.dropFirst("collector-gap-".count))] != nil {
            return "本项采集器尚未接入"
        }
        if source.hasPrefix("adapter-") { return "检查适配器 \(source.suffix(1))" }
        return "检查来源"
    }

    private func contextTitle(_ context: GuardAssessmentContext?) -> String {
        switch context {
        case .claudeLaunch: return "最近一次 Claude 启动检查"
        case .managedSession: return "受管会话"
        case .agentDefault: return "后台默认环境"
        default: return "检查快照"
        }
    }
}

private struct ReportSummaryMetric: View {
    let value: Int
    let label: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("\(value)")
                .guardFont(size: 19, weight: .bold, design: .rounded)
                .monospacedDigit()
                .foregroundStyle(tint)
            Text(label)
                .guardFont(size: 10, weight: .medium)
                .foregroundStyle(MenuPalette.muted)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.leading, 13)
        .accessibilityElement(children: .combine)
    }
}
