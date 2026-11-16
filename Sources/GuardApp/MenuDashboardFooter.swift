import SwiftUI

struct MenuDashboardFooter: View {
    let isChecking: Bool
    let refresh: () -> Void
    let openSettings: () -> Void
    let openReport: () -> Void
    let openIntegration: () -> Void

    var body: some View {
        VStack(spacing: 9) {
            Button(action: refresh) {
                HStack(spacing: 7) {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 12, weight: .bold))
                    Text("立即检测")
                        .guardFont(size: 12, weight: .bold)
                }
                .frame(maxWidth: .infinity, minHeight: 19)
            }
            .buttonStyle(AccentButtonStyle())
            .disabled(isChecking)

            HStack(spacing: 8) {
                secondaryAction("集成", symbol: "point.3.connected.trianglepath.dotted",
                                accessibilityLabel: "管理 Claude Code 集成",
                                action: openIntegration)
                secondaryAction("规则", symbol: "list.bullet.rectangle",
                                accessibilityLabel: "查看全量规则报告",
                                action: openReport)
                secondaryAction("设置", symbol: "slider.horizontal.3",
                                accessibilityLabel: "打开 SafeClaude 设置",
                                action: openSettings)
            }
        }
        .padding(.horizontal, 22)
        .padding(.top, 11)
        .padding(.bottom, 13)
        .overlay(alignment: .top) { Rectangle().fill(MenuPalette.line).frame(height: 1) }
    }

    private func secondaryAction(_ title: String, symbol: String,
                                 accessibilityLabel: String,
                                 action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label {
                Text(title).guardFont(size: 11, weight: .semibold)
            } icon: {
                Image(systemName: symbol).font(.system(size: 11, weight: .semibold))
            }
            .frame(maxWidth: .infinity, minHeight: 18)
        }
        .buttonStyle(SecondaryButtonStyle())
        .accessibilityLabel(accessibilityLabel)
        .help(accessibilityLabel)
    }
}
