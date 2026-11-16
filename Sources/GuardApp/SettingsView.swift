import SwiftUI

struct SettingsView: View {
    @ObservedObject var model: SettingsModel
    @ObservedObject var menuModel: MenuModel
    @State private var section = SettingsSection.protection
    @State private var showingClearConfirmation = false

    var body: some View {
        HStack(spacing: 0) {
            SettingsSidebar(selection: $section)
            Rectangle().fill(SettingsPalette.line).frame(width: 1)
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    SettingsPageHeader(section: section)
                    pageContent
                    if let notice = model.notice {
                        SettingsNotice(text: notice, isError: model.noticeIsError)
                    }
                }
                .padding(.horizontal, 36)
                .padding(.vertical, 30)
                .frame(maxWidth: 900, alignment: .leading)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(SettingsPalette.canvas)
        }
        .frame(minWidth: 900, minHeight: 660)
        .background(SettingsPalette.canvas)
        .onAppear(perform: load)
        .confirmationDialog("清除本机网络历史？", isPresented: $showingClearConfirmation) {
            Button("清除历史", role: .destructive, action: confirmClearHistory)
            Button("取消", role: .cancel) {}
        } message: {
            Text("这会删除用于记录出口变化的本机历史摘要，不会影响 Claude 配置。")
        }
    }

    @ViewBuilder
    private var pageContent: some View {
        switch section {
        case .protection:
            ProtectionSettingsPage(model: model)
        case .sessions:
            ManagedSessionsPage(model: model)
        case .network:
            NetworkPrivacySettingsPage(model: model)
        case .data:
            LocalDataSettingsPage(
                model: model,
                clearHistory: { showingClearConfirmation = true },
                exportDiagnostics: { model.exportDiagnostics(response: menuModel.response) }
            )
        }
    }

    private func load() {
        model.load()
    }

    private func confirmClearHistory() {
        Task {
            await model.clearHistory()
            menuModel.refresh()
        }
    }
}
