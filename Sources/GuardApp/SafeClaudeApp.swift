import SwiftUI
import AgentSupervisorSupport
import AppKit

enum SafeClaudeBrand {
    static let menuBarMark: NSImage? = {
        guard let url = Bundle.main.url(forResource: "MenuBarMark", withExtension: "png"),
              let image = NSImage(contentsOf: url) else { return nil }
        image.isTemplate = true
        return image
    }()
}

@main
struct SafeClaudeApp: App {
    @StateObject private var menuModel = MenuModel()
    @StateObject private var settingsModel = SettingsModel()
    @StateObject private var integrationModel = IntegrationSetupModel()

    init() {
        Task { @MainActor in
            await AgentSupervisor.shared.monitor()
        }
    }

    var body: some Scene {
        MenuBarExtra {
            MenuView(model: menuModel, integrationModel: integrationModel)
        } label: {
            HStack(spacing: 4) {
                if let mark = SafeClaudeBrand.menuBarMark {
                    Image(nsImage: mark)
                        .accessibilityLabel("SafeClaude")
                } else {
                    Image(systemName: "shield.lefthalf.filled")
                        .accessibilityLabel("SafeClaude")
                }
                Text(menuBarValue)
                    .monospacedDigit()
            }
            .task {
                while !Task.isCancelled {
                    menuModel.refresh()
                    try? await Task.sleep(for: .seconds(10))
                }
            }
        }
        .menuBarExtraStyle(.window)

        Window("SafeClaude 设置", id: "settings") {
            SettingsView(model: settingsModel, menuModel: menuModel)
        }
        .defaultSize(width: 1000, height: 760)
        .windowResizability(.automatic)

        Window("Claude Code 接入", id: "integration") {
            IntegrationSetupView(model: integrationModel, onIntegrationChanged: {
                menuModel.refresh()
            })
        }
        .defaultSize(width: 740, height: 620)
        .windowResizability(.automatic)

        Window("全量规则报告", id: "report") {
            RuleReportView(response: menuModel.response)
        }
        .defaultSize(width: 820, height: 720)
    }

    private var menuBarValue: String {
        if let score = menuModel.response?.safetyScore { return String(score) }
        if menuModel.response != nil { return "—" }
        return menuModel.checking ? "…" : "!"
    }
}
