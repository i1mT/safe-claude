import Foundation
import UserNotifications
import GuardCore

@MainActor
final class GuardNotificationCoordinator: NSObject {
    static let shared = GuardNotificationCoordinator()

    private let center = UNUserNotificationCenter.current()
    private let notificationID = "safeclaude.environment-status"
    private let activeKey = "safeclaude.environment-alert-active"

    private override init() {
        super.init()
        center.delegate = self
    }

    func requestPermission() async throws {
        let settings = await center.notificationSettings()
        switch settings.authorizationStatus {
        case .authorized, .provisional:
            return
        case .denied:
            throw NotificationSetupError.denied
        case .notDetermined:
            let granted = try await center.requestAuthorization(options: [.alert])
            guard granted else { throw NotificationSetupError.denied }
        @unknown default:
            throw NotificationSetupError.unavailable
        }
    }

    func setEnabled(_ enabled: Bool) {
        guard !enabled else { return }
        UserDefaults.standard.set(false, forKey: activeKey)
        center.removePendingNotificationRequests(withIdentifiers: [notificationID])
    }

    func update(decision: String, enabled: Bool) {
        guard enabled else {
            setEnabled(false)
            return
        }

        let previousActive = UserDefaults.standard.bool(forKey: activeKey)
        let transition = GuardNotificationTransition.next(isActive: previousActive, decision: decision)
        UserDefaults.standard.set(transition.active, forKey: activeKey)
        guard transition.event != .none else { return }

        let content = UNMutableNotificationContent()
        switch transition.event {
        case .risk:
            content.title = decision == "deny" ? "Claude Code 启动保护已拦截" : "Claude Code 环境待确认"
            content.body = "SafeClaude 检测到环境状态变化。打开菜单栏查看检查结果。"
        case .recovered:
            content.title = "Claude Code 环境检查已恢复"
            content.body = "SafeClaude 已重新确认当前环境。"
        case .none:
            return
        }
        content.sound = nil
        let request = UNNotificationRequest(
            identifier: notificationID,
            content: content,
            trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
        )

        center.removePendingNotificationRequests(withIdentifiers: [notificationID])
        center.add(request) { _ in }
    }
}

enum NotificationSetupError: Error {
    case denied
    case unavailable
}

extension GuardNotificationCoordinator: UNUserNotificationCenterDelegate {
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list])
    }
}
