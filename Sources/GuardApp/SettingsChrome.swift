import SwiftUI
import AppKit

struct SettingsSidebar: View {
    @Binding var selection: SettingsSection

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 11) {
                Group {
                    if let mark = SafeClaudeBrand.menuBarMark {
                        Image(nsImage: mark)
                            .resizable()
                            .renderingMode(.template)
                            .scaledToFit()
                            .padding(10)
                    } else {
                        Image(systemName: "shield.lefthalf.filled")
                            .font(.system(size: 17, weight: .semibold))
                    }
                }
                .foregroundStyle(GuardPalette.ink)
                .frame(width: 38, height: 38)
                .background(GuardPalette.lime, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text("SafeClaude")
                        .guardFont(size: 15, weight: .bold)
                        .foregroundStyle(GuardPalette.paper)
                    Text("菜单栏安全监测")
                        .guardFont(size: 11, weight: .medium)
                        .foregroundStyle(GuardPalette.muted)
                }
            }
            .padding(.horizontal, 17)
            .padding(.top, 25)
            .padding(.bottom, 20)

            Text("设置")
                .guardFont(size: 12, weight: .semibold)
                .foregroundStyle(GuardPalette.muted)
                .padding(.horizontal, 20)
                .padding(.bottom, 3)

            ForEach(SettingsSection.allCases) { item in
                Button { selection = item } label: {
                    HStack(spacing: 11) {
                        Image(systemName: item.symbol)
                            .font(.system(size: 14, weight: selection == item ? .semibold : .regular))
                            .frame(width: 19)
                        Text(item.title)
                            .guardFont(size: 13, weight: selection == item ? .semibold : .medium)
                        Spacer()
                    }
                    .foregroundStyle(selection == item ? GuardPalette.paper : GuardPalette.muted)
                    .padding(.horizontal, 12)
                    .frame(height: 38)
                    .background {
                        if selection == item {
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .fill(MenuPalette.accentInk.opacity(0.12))
                                .overlay(alignment: .leading) {
                                    Capsule()
                                        .fill(MenuPalette.accentInk)
                                        .frame(width: 3, height: 18)
                                        .padding(.leading, 1)
                                }
                        }
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel(item.title)
                .accessibilityAddTraits(selection == item ? .isSelected : [])
                .padding(.horizontal, 10)
            }
            Spacer()
            Label("数据仅保存在本机", systemImage: "lock.shield")
                .guardFont(size: 11, weight: .medium)
                .foregroundStyle(GuardPalette.muted)
                .padding(.horizontal, 19)
                .padding(.bottom, 18)
        }
        .frame(width: 226)
        .background(GuardPalette.ink)
    }
}

struct SettingsPageHeader: View {
    let section: SettingsSection

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(section.title, systemImage: section.symbol)
                .guardFont(size: 25, weight: .semibold)
                .foregroundStyle(SettingsPalette.text)
                .labelStyle(.titleAndIcon)
            Text(section.subtitle)
                .guardFont(size: 14)
                .foregroundStyle(SettingsPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.bottom, 8)
    }
}

struct SettingsNotice: View {
    let text: String
    let isError: Bool

    var body: some View {
        Label(text, systemImage: isError ? "exclamationmark.circle" : "checkmark.circle")
            .guardFont(size: 11, weight: .medium)
            .foregroundStyle(isError ? SettingsPalette.danger : SettingsPalette.success)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(isError ? SettingsPalette.dangerBackground : SettingsPalette.successBackground,
                        in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}
