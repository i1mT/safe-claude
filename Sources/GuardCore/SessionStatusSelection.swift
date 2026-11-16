import Foundation

/// A menu-bar summary must represent the least safe active protected session,
/// rather than silently replacing it with the agent's own launch environment.
public enum SessionStatusSelection {
    public static func worst(_ statuses: [GuardResponse], at now: Date = Date(),
                             maximumAge: TimeInterval = 45) -> GuardResponse? {
        guard !statuses.isEmpty else { return nil }
        guard maximumAge.isFinite, maximumAge >= 0 else {
            return GuardResponse(decision: "hold", reason: "受管会话状态无法确认。")
        }
        if statuses.contains(where: { !(0...maximumAge).contains(now.timeIntervalSince($0.checkedAt)) }) {
            return GuardResponse(decision: "hold", reason: "受管会话状态已过期，正在重新检查。")
        }
        func severity(_ status: GuardResponse) -> Int {
            switch status.decision {
            case "allow": return 0
            case "warning": return 1
            default: return 2
            }
        }
        return statuses.sorted {
            let left = severity($0), right = severity($1)
            if left != right { return left > right }
            let a = $0.safetyScore ?? $0.scoreUpperBound ?? -1
            let b = $1.safetyScore ?? $1.scoreUpperBound ?? -1
            if a != b { return a < b }
            return $0.checkedAt < $1.checkedAt
        }.first
    }
}
