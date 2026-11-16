import Foundation

public enum GuardNotificationEvent: Equatable, Sendable {
    case none
    case risk
    case recovered
}

public enum GuardNotificationTransition {
    /// Treat every non-allow decision as an active condition. A persistent
    /// hold/deny emits once, and a later allow emits one recovery event.
    public static func next(isActive: Bool, decision: String) -> (active: Bool, event: GuardNotificationEvent) {
        let nextActive = decision != "allow"
        guard nextActive != isActive else { return (isActive, .none) }
        return (nextActive, nextActive ? .risk : .recovered)
    }
}
