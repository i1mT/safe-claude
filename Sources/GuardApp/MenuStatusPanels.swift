import SwiftUI
import AppKit

struct MenuMasthead: View {
    let connectionLabel: String
    let statusColor: Color
    let isChecking: Bool

    var body: some View {
        HStack(spacing: 11) {
            Group {
                if let mark = SafeClaudeBrand.menuBarMark {
                    Image(nsImage: mark)
                        .resizable()
                        .renderingMode(.template)
                        .scaledToFit()
                        .foregroundStyle(MenuPalette.accentText)
                        .frame(width: 19, height: 19)
                } else {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundStyle(MenuPalette.accentText)
                }
            }
                .frame(width: 30, height: 30)
                .background(MenuPalette.accent, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text("SafeClaude")
                    .guardFont(size: 14, weight: .bold)
                    .foregroundStyle(MenuPalette.ink)
                Text("运行环境监测")
                    .guardFont(size: 10, weight: .medium)
                    .foregroundStyle(MenuPalette.muted)
            }
            Spacer()
            HStack(spacing: 6) {
                Circle().fill(isChecking ? MenuPalette.amber : statusColor).frame(width: 6, height: 6)
                Text(connectionLabel)
                    .guardFont(size: 10, weight: .bold)
                    .foregroundStyle(MenuPalette.ink.opacity(0.84))
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(MenuPalette.surface, in: Capsule())
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 14)
        .overlay(alignment: .bottom) { Rectangle().fill(MenuPalette.line).frame(height: 1) }
    }
}

struct MenuScorePanel: View {
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    let score: Int?
    let upperBound: Int?
    let scoreText: String
    let title: String
    let decision: String?
    let thresholdText: String?
    let thresholdDetail: String?
    let isChecking: Bool
    let checkedAt: Date?
    let accessibleLabel: String

    private var instrumentStatusColor: Color {
        switch decision {
        case "allow": return MenuPalette.instrumentAccent
        case "warning", "hold": return Color(hex: 0xF2C66D)
        case "deny": return Color(hex: 0xFF8C82)
        default: return Color(hex: 0xF2C66D)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 17) {
            HStack(alignment: .firstTextBaseline) {
                Text("环境安全分")
                    .guardFont(size: 12, weight: .semibold)
                    .foregroundStyle(MenuPalette.instrumentMuted)
                Spacer()
                Text(sampleLabel)
                    .guardFont(size: 10, weight: .medium, design: .monospaced)
                    .foregroundStyle(MenuPalette.instrumentMuted)
                    .accessibilityHidden(true)
            }

            if dynamicTypeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: 15) {
                    HStack {
                        Spacer(minLength: 0)
                        scoreDial
                        Spacer(minLength: 0)
                    }
                    decisionContent
                }
            } else {
                HStack(spacing: 20) {
                    scoreDial
                    decisionContent
                }
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 17)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(MenuPalette.instrument, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
        .overlay(alignment: .leading) {
            RoundedRectangle(cornerRadius: 1)
                .fill(instrumentStatusColor)
                .frame(width: 2, height: 52)
                .padding(.leading, 1)
        }
        .overlay {
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .stroke(MenuPalette.instrumentLine, lineWidth: 1)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibleLabel)
    }

    private var scoreDial: some View {
        ScoreDial(score: score, upperBound: upperBound, scoreText: scoreText,
                  tint: instrumentStatusColor)
            .accessibilityHidden(true)
    }

    private var decisionContent: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 7) {
                Image(systemName: statusSymbol)
                    .font(.system(size: 13, weight: .bold))
                    .accessibilityHidden(true)
                Text(title)
                    .guardFont(size: 15, weight: .bold)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .foregroundStyle(instrumentStatusColor)

            Rectangle()
                .fill(MenuPalette.instrumentLine)
                .frame(height: 1)

            VStack(alignment: .leading, spacing: 4) {
                Text(thresholdText ?? (isChecking ? "正在检查环境" : "分数越高，当前环境越安全"))
                    .guardFont(size: 11, weight: .semibold)
                    .foregroundStyle(MenuPalette.instrumentInk)
                    .fixedSize(horizontal: false, vertical: true)
                Text(score == nil && upperBound != nil
                     ? "必要检查完成前不会放行"
                     : (thresholdDetail ?? "策略按当前设置执行"))
                    .guardFont(size: 10, weight: .medium)
                    .foregroundStyle(MenuPalette.instrumentMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if score == nil, let upperBound {
                Label("显示的是分数上限 \(upperBound)", systemImage: "exclamationmark.triangle.fill")
                    .guardFont(size: 10, weight: .semibold)
                    .foregroundStyle(Color(hex: 0xF2C66D))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var sampleLabel: String {
        guard let checkedAt else { return isChecking ? "正在采样" : "尚无样本" }
        return "采样 · " + checkedAt.formatted(date: .omitted, time: .shortened)
    }

    private var statusSymbol: String {
        switch decision {
        case "allow": return "checkmark.shield.fill"
        case "warning": return "exclamationmark.shield.fill"
        case "hold": return "questionmark.diamond.fill"
        case "deny": return "xmark.shield.fill"
        default: return isChecking ? "arrow.clockwise" : "shield.lefthalf.filled"
        }
    }
}

private struct ScoreDial: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ScaledMetric(relativeTo: .largeTitle) private var diameter: CGFloat = 98
    let score: Int?
    let upperBound: Int?
    let scoreText: String
    let tint: Color

    private let tickCount = 48
    private let sweep = 286.0

    var body: some View {
        ZStack {
            Canvas { context, size in
                let center = CGPoint(x: size.width / 2, y: size.height / 2)
                let radius = min(size.width, size.height) / 2 - 3
                let activeValue = max(0, min(100, score ?? upperBound ?? 0))
                let activeCount = Int((Double(activeValue) / 100 * Double(tickCount)).rounded(.down))
                for index in 0..<tickCount {
                    let angle = (-137.0 + Double(index) * sweep / Double(tickCount - 1)) * .pi / 180
                    let major = index.isMultiple(of: 4)
                    let inner = radius - (major ? 9 : 5)
                    let start = CGPoint(x: center.x + cos(angle) * inner,
                                        y: center.y + sin(angle) * inner)
                    let end = CGPoint(x: center.x + cos(angle) * radius,
                                      y: center.y + sin(angle) * radius)
                    var path = Path()
                    path.move(to: start)
                    path.addLine(to: end)
                    let active = index < activeCount
                    context.stroke(path,
                                   with: .color(active ? tint.opacity(score == nil ? 0.38 : 1)
                                                       : MenuPalette.instrumentLine),
                                   style: StrokeStyle(lineWidth: major ? 2.5 : 1.5,
                                                      lineCap: .round))
                }
            }
            VStack(spacing: 0) {
                Text(scoreText)
                    .guardFont(size: 34, weight: .bold, design: .rounded)
                    .monospacedDigit()
                    .tracking(-1.8)
                    .contentTransition(.numericText())
                    .foregroundStyle(MenuPalette.instrumentInk)
                    .lineLimit(1)
                    .minimumScaleFactor(0.65)
                Text("安全分")
                    .guardFont(size: 9, weight: .medium)
                    .foregroundStyle(MenuPalette.instrumentMuted)
            }
        }
        .frame(width: diameter, height: diameter)
        .animation(reduceMotion ? nil : .easeOut(duration: 0.28), value: score)
    }
}

struct MenuOfflineSection: View {
    let isChecking: Bool
    let isStale: Bool
    let reconnect: () -> Void

    private var detail: String {
        if isStale { return "上次状态已过期。刷新连接后，SafeClaude 会重新读取当前策略。" }
        if isChecking { return "正在连接本机 Agent 并读取当前环境检查结果。" }
        return "无法连接本机 Agent。请确认 SafeClaude 后台服务已安装并运行。"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            MenuSectionHeading(title: "服务状态")
            Text(detail)
                .guardFont(size: 13)
                .foregroundStyle(MenuPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 2)
            Button(action: reconnect) {
                Label("重新连接", systemImage: "arrow.clockwise")
                    .guardFont(size: 12, weight: .semibold)
                    .foregroundStyle(MenuPalette.accentText)
                    .padding(.horizontal, 13)
                    .padding(.vertical, 8)
                .background(MenuPalette.accent, in: Capsule())
            }
            .buttonStyle(.plain)
            .disabled(isChecking)
            .padding(.top, 3)
        }
    }
}

struct MenuSetupPrompt: View {
    let openSetup: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 13) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(MenuPalette.accentInk)
                .frame(width: 34, height: 34)
                .background(MenuPalette.raised, in: RoundedRectangle(cornerRadius: 9))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("Claude Code 尚未接入")
                    .guardFont(size: 12, weight: .bold)
                    .foregroundStyle(MenuPalette.ink)
                Text("完成本机设置后，启动命令才会经过保护。")
                    .guardFont(size: 10, weight: .medium)
                    .foregroundStyle(MenuPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 6)
            Button("开始设置", action: openSetup)
                .buttonStyle(AccentButtonStyle())
                .accessibilityHint("选择 Claude Code 并安装本机启动集成")
        }
        .padding(12)
        .background(MenuPalette.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(MenuPalette.line, lineWidth: 1)
        }
        .accessibilityElement(children: .contain)
    }
}

struct MenuSectionHeading: View {
    let title: String

    var body: some View {
        Text(title)
            .guardFont(size: 14, weight: .bold)
            .foregroundStyle(MenuPalette.ink)
    }
}
