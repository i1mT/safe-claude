import SwiftUI
import GuardCore

struct MenuFindingSection: View {
    let response: GuardResponse

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                MenuSectionHeading(title: "环境信号")
                Spacer()
                Text("\(response.findings.count) 个触发项")
                    .guardFont(size: 12, weight: .medium)
                    .foregroundStyle(MenuPalette.muted)
            }
            if response.findings.isEmpty {
                HStack(spacing: 9) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(MenuPalette.accentInk)
                    Text("目前没有已触发的扣分项")
                        .foregroundStyle(MenuPalette.ink.opacity(0.9))
                    Spacer()
                }
                    .guardFont(size: 13, weight: .medium)
                .padding(.vertical, 11)
                .overlay(alignment: .top) { Rectangle().fill(MenuPalette.line).frame(height: 1) }
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(response.findings.prefix(4)), id: \.rule) { finding in
                        HStack(spacing: 10) {
                            Text(RuleLabels.chinese[finding.rule] ?? finding.rule)
                                .guardFont(size: 13, weight: .medium)
                                .foregroundStyle(MenuPalette.ink)
                                .lineLimit(1)
                            Spacer(minLength: 6)
                            Text("−\(finding.points)")
                                .guardFont(size: 12, weight: .bold, design: .monospaced)
                                .monospacedDigit()
                                .foregroundStyle(MenuPalette.coral)
                        }
                        .padding(.vertical, 10)
                        .overlay(alignment: .bottom) {
                            Rectangle().fill(MenuPalette.line).frame(height: 1)
                        }
                    }
                }
                if response.findings.count > 4 {
                    Text("以及另外 \(response.findings.count - 4) 项")
                        .guardFont(size: 12, weight: .medium)
                        .foregroundStyle(MenuPalette.muted)
                        .padding(.top, 2)
                }
            }
        }
    }
}

struct MenuCoverageSection: View {
    let response: GuardResponse

    private var lastChecked: String {
        let seconds = max(0, Int(Date().timeIntervalSince(response.checkedAt)))
        if seconds < 60 { return "刚刚" }
        if seconds < 3600 { return "\(seconds / 60) 分钟" }
        return response.checkedAt.formatted(date: .omitted, time: .shortened)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            MenuSectionHeading(title: "状态摘要")
            HStack(spacing: 0) {
                MenuCoverageMetric(value: "\(response.unknownCount)",
                                   label: "待确认",
                                   tint: response.unknownCount == 0 ? MenuPalette.accentInk : MenuPalette.amber)
                Rectangle().fill(MenuPalette.line).frame(width: 1, height: 28)
                MenuCoverageMetric(value: response.managedSessions.map(String.init) ?? "—",
                                   label: "受管会话",
                                   tint: MenuPalette.ink)
                Rectangle().fill(MenuPalette.line).frame(width: 1, height: 28)
                MenuCoverageMetric(value: lastChecked, label: "最近检查", tint: MenuPalette.ink)
            }
            if let rules = response.unknownRules, !rules.isEmpty {
                DisclosureGroup {
                    VStack(alignment: .leading, spacing: 7) {
                        ForEach(rules, id: \.self) { rule in
                            HStack(alignment: .top, spacing: 7) {
                                Circle().fill(MenuPalette.amber).frame(width: 5, height: 5).padding(.top, 4)
                                Text(RuleLabels.chinese[rule] ?? rule)
                                    .guardFont(size: 11)
                                    .foregroundStyle(MenuPalette.muted)
                            }
                        }
                    }
                    .padding(.top, 9)
                } label: {
                    Text("查看 \(response.unknownCount) 项待确认")
                        .guardFont(size: 11, weight: .semibold)
                        .foregroundStyle(MenuPalette.amber)
                }
                .tint(MenuPalette.amber)
            }
        }
        .padding(.top, 2)
    }
}

private struct MenuCoverageMetric: View {
    let value: String
    let label: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(value)
                .guardFont(size: 13, weight: .bold, design: .monospaced)
                .monospacedDigit()
                .foregroundStyle(tint)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
                Text(label)
                .guardFont(size: 11, weight: .medium)
                .foregroundStyle(MenuPalette.muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.leading, 12)
        .padding(.vertical, 2)
    }
}
