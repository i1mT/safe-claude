import SwiftUI
import AppKit

private struct ScaledSystemFont: ViewModifier {
    @ScaledMetric(relativeTo: .body) private var scaledSize: CGFloat = 12
    private let weight: Font.Weight
    private let design: Font.Design

    init(size: CGFloat, weight: Font.Weight, design: Font.Design) {
        _scaledSize = ScaledMetric(wrappedValue: size, relativeTo: .body)
        self.weight = weight
        self.design = design
    }

    func body(content: Content) -> some View {
        content.font(.system(size: scaledSize, weight: weight, design: design))
    }
}

extension View {
    func guardFont(size: CGFloat, weight: Font.Weight = .regular,
                   design: Font.Design = .default) -> some View {
        modifier(ScaledSystemFont(size: size, weight: weight, design: design))
    }

    func guardInput() -> some View {
        modifier(GuardInputModifier())
    }
}

private struct GuardInputModifier: ViewModifier {
    @FocusState private var isFocused: Bool

    func body(content: Content) -> some View {
        content
            .textFieldStyle(.plain)
            .foregroundStyle(SettingsPalette.text)
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(SettingsPalette.row, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(isFocused ? SettingsPalette.accent : SettingsPalette.line,
                            lineWidth: isFocused ? 1.5 : 1)
            }
            .focused($isFocused)
    }
}

enum GuardPalette {
    static let ink = MenuPalette.canvas
    static let raised = MenuPalette.raised
    static let line = MenuPalette.line
    static let paper = MenuPalette.ink
    static let muted = MenuPalette.muted
    static let lime = MenuPalette.accent
    static let coral = MenuPalette.coral
    static let amber = MenuPalette.amber
}

/// SafeClaude uses a restrained native palette that follows macOS appearance.
/// Chartreuse is reserved for the brand and primary action; status text uses
/// contrast-safe semantic variants.
enum MenuPalette {
    static let canvas = adaptive(light: 0xF3F5F2, dark: 0x141916,
                                 lightContrast: 0xFFFFFF, darkContrast: 0x000000)
    /// The score instrument is deliberately darker than its surrounding
    /// surface so the primary decision reads as a distinct control surface.
    static let instrument = adaptive(light: 0x18231C, dark: 0x0D130F,
                                    lightContrast: 0x000000, darkContrast: 0x000000)
    static let instrumentInk = Color(hex: 0xF3F7F1)
    static let instrumentMuted = Color(hex: 0xAAB8AD)
    static let instrumentLine = Color(hex: 0x37443A)
    static let instrumentAccent = Color(hex: 0xC4EA8C)
    static let surface = adaptive(light: 0xFFFFFF, dark: 0x1E2520,
                                  lightContrast: 0xFFFFFF, darkContrast: 0x171C19)
    static let raised = adaptive(light: 0xE8ECE8, dark: 0x2A332D,
                                 lightContrast: 0xE1E6E2, darkContrast: 0x333D37)
    static let ink = adaptive(light: 0x1B241E, dark: 0xF1F5EF,
                              lightContrast: 0x000000, darkContrast: 0xFFFFFF)
    static let muted = adaptive(light: 0x55635A, dark: 0xB5BEB6,
                                lightContrast: 0x3B4940, darkContrast: 0xE3EBE5)
    static let line = adaptive(light: 0xD4DBD5, dark: 0x3D4941,
                               lightContrast: 0x68736B, darkContrast: 0x89958D)
    static let accent = adaptive(light: 0xBDE58A, dark: 0xBDE58A,
                                 lightContrast: 0xC1E787, darkContrast: 0xC1E787)
    static let accentText = Color(hex: 0x172014)
    static let accentInk = adaptive(light: 0x3E651A, dark: 0xC6EA91,
                                    lightContrast: 0x345A12, darkContrast: 0xC7F090)
    static let coral = adaptive(light: 0xB9382F, dark: 0xFF8C82,
                                lightContrast: 0x9E2D25, darkContrast: 0xFF9B92)
    static let amber = adaptive(light: 0x895900, dark: 0xF1C774,
                                lightContrast: 0x754C00, darkContrast: 0xFFD98A)

    static func adaptive(light: UInt32, dark: UInt32,
                         lightContrast: UInt32, darkContrast: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let match = appearance.bestMatch(from: [
                .accessibilityHighContrastAqua, .accessibilityHighContrastDarkAqua, .aqua, .darkAqua
            ])
            let highContrast = match == .accessibilityHighContrastAqua ||
                match == .accessibilityHighContrastDarkAqua
            let isDark = match == .darkAqua || match == .accessibilityHighContrastDarkAqua
            let hex = highContrast ? (isDark ? darkContrast : lightContrast) : (isDark ? dark : light)
            return NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
                           green: CGFloat((hex >> 8) & 0xFF) / 255,
                           blue: CGFloat(hex & 0xFF) / 255,
                           alpha: 1)
        })
    }
}

enum SettingsPalette {
    static let canvas = MenuPalette.canvas
    static let card = MenuPalette.surface
    static let text = MenuPalette.ink
    static let muted = MenuPalette.muted
    static let line = MenuPalette.line
    static let row = MenuPalette.raised
    static let accent = MenuPalette.accentInk
    static let danger = MenuPalette.coral
    static let success = MenuPalette.accentInk
    static let successBackground = MenuPalette.adaptive(
        light: 0xE8F3DE, dark: 0x263620, lightContrast: 0xDDEFD0, darkContrast: 0x1B2C15)
    static let dangerBackground = MenuPalette.adaptive(
        light: 0xFCE8E5, dark: 0x422A25, lightContrast: 0xF8DAD6, darkContrast: 0x361B17)
    static let accentFill = MenuPalette.accent
}

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: 1
        )
    }
}

enum SettingsSection: String, CaseIterable, Identifiable {
    case protection
    case sessions
    case network
    case data
    var id: String { rawValue }
    var title: String {
        switch self {
        case .protection: return "防护策略"
        case .sessions: return "受管会话"
        case .network: return "网络与隐私"
        case .data: return "数据与诊断"
        }
    }
    var subtitle: String {
        switch self {
        case .protection: return "设置 Claude Code 的启动与运行中安全门槛。"
        case .sessions: return "查看 SafeClaude 正在保护的 Claude Code 进程。"
        case .network: return "管理出口地理查询及网络路径评估所需的数据授权。"
        case .data: return "控制可选信誉凭据与本机检测历史。"
        }
    }
    var symbol: String {
        switch self {
        case .protection: return "shield.lefthalf.filled"
        case .sessions: return "terminal"
        case .network: return "point.3.connected.trianglepath.dotted"
        case .data: return "externaldrive"
        }
    }
}

struct AccentButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .guardFont(size: 12, weight: .bold)
            .foregroundStyle(isEnabled ? MenuPalette.accentText : MenuPalette.muted)
            .padding(.horizontal, 13)
            .padding(.vertical, 9)
            .background(isEnabled
                        ? MenuPalette.accent.opacity(configuration.isPressed ? 0.78 : 1)
                        : MenuPalette.raised,
                        in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(isEnabled ? MenuPalette.accent : MenuPalette.line, lineWidth: 1)
            }
            .scaleEffect(isEnabled && !reduceMotion && configuration.isPressed ? 0.98 : 1)
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .guardFont(size: 12, weight: .semibold)
            .foregroundStyle(isEnabled ? SettingsPalette.text : SettingsPalette.muted)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(isEnabled && configuration.isPressed
                        ? SettingsPalette.row : SettingsPalette.card,
                        in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(isEnabled ? SettingsPalette.line : SettingsPalette.line.opacity(0.65),
                            lineWidth: 1)
            }
    }
}

struct DestructiveButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .guardFont(size: 12, weight: .semibold)
            .foregroundStyle(isEnabled ? MenuPalette.coral : MenuPalette.muted)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(isEnabled && configuration.isPressed
                        ? MenuPalette.coral.opacity(0.14) : MenuPalette.surface,
                        in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(isEnabled ? MenuPalette.coral.opacity(0.55) : MenuPalette.line,
                            lineWidth: 1)
            }
            .scaleEffect(isEnabled && !reduceMotion && configuration.isPressed ? 0.98 : 1)
    }
}

struct StepperButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .guardFont(size: 10, weight: .bold)
            .foregroundStyle(isEnabled ? SettingsPalette.text : SettingsPalette.muted)
            .background(isEnabled && configuration.isPressed
                        ? SettingsPalette.row : SettingsPalette.canvas,
                        in: RoundedRectangle(cornerRadius: 7, style: .continuous))
    }
}
