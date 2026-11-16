import Foundation

public enum ClaudeModelLifecycleStatus: String, Codable, Sendable {
    case active, deprecated, retired
}

public enum ClaudeModelAssessment: Equatable, Sendable {
    case active
    case attention
    case unknown
}

public enum ClaudeModelLifecycle {
    private struct Snapshot: Decodable {
        struct Model: Decodable {
            let id: String
            let status: ClaudeModelLifecycleStatus
            let deprecatedAt: String?
            let retiredAt: String?
        }
        let schemaVersion: Int
        let observedAt: String
        let aliasObservedAt: String
        let aliases: [String: String]
        let models: [Model]
    }

    /// Model identifiers are retained only after strict syntax validation.
    /// Model aliases are resolved only through the dated official mapping;
    /// provider-specific deployment names remain unknown.
    public static func isValidIdentifier(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 128,
              value.utf8.allSatisfy({
                  (65...90).contains($0) || (97...122).contains($0) ||
                  (48...57).contains($0) || [45, 46, 95, 91, 93].contains($0)
              }) else { return false }
        return true
    }

    public static func assess(_ identifiers: Set<String>, at date: Date = Date()) -> ClaudeModelAssessment {
        guard !identifiers.isEmpty, identifiers.count <= 8,
              identifiers.allSatisfy(isValidIdentifier),
              let data = try? Data(contentsOf: Bundle.module.url(
                forResource: "claude-model-lifecycle", withExtension: "json")!),
              let snapshot = try? JSONDecoder().decode(Snapshot.self, from: data),
              snapshot.schemaVersion == 1,
              let observedAt = day(snapshot.observedAt), observedAt <= date,
              date.timeIntervalSince(observedAt) <= 45 * 24 * 60 * 60,
              let aliasObservedAt = day(snapshot.aliasObservedAt), aliasObservedAt <= date,
              date.timeIntervalSince(aliasObservedAt) <= 45 * 24 * 60 * 60,
              snapshot.models.count <= 256,
              Set(snapshot.models.map(\.id)).count == snapshot.models.count,
              snapshot.aliases.count <= 32,
              snapshot.aliases.keys.allSatisfy(isValidIdentifier),
              snapshot.aliases.values.allSatisfy(isValidIdentifier) else {
            return .unknown
        }
        let models = Dictionary(uniqueKeysWithValues: snapshot.models.map { ($0.id, $0) })
        var requiresAttention = false
        for suppliedIdentifier in identifiers {
            let identifier = snapshot.aliases[suppliedIdentifier] ?? suppliedIdentifier
            guard let model = models[identifier] else { return .unknown }
            switch assess(status: model.status, deprecatedAt: model.deprecatedAt,
                          retiredAt: model.retiredAt, at: date) {
            case .active: break
            case .attention: requiresAttention = true
            case .unknown: return .unknown
            }
        }
        return requiresAttention ? .attention : .active
    }

    static func assess(status: ClaudeModelLifecycleStatus, deprecatedAt: String?,
                       retiredAt: String?, at date: Date) -> ClaudeModelAssessment {
        let deprecatedDate = deprecatedAt.flatMap(effectiveDay)
        let retiredDate = retiredAt.flatMap(effectiveDay)
        if deprecatedAt != nil && deprecatedDate == nil || retiredAt != nil && retiredDate == nil {
            return .unknown
        }
        switch status {
        case .active:
            if let deprecatedDate, deprecatedDate <= date { return .attention }
            if let retiredDate, retiredDate <= date { return .attention }
            return .active
        case .deprecated:
            guard let deprecatedDate else { return .unknown }
            return deprecatedDate <= date ? .attention : .active
        case .retired:
            if let retiredDate, retiredDate <= date { return .attention }
            if let deprecatedDate, deprecatedDate <= date { return .attention }
            guard retiredAt != nil || deprecatedAt != nil else { return .unknown }
            return .active
        }
    }

    private static func day(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        return formatter.date(from: value)
    }

    /// Wait until the official calendar date has begun in every time zone.
    private static func effectiveDay(_ value: String) -> Date? {
        day(value)?.addingTimeInterval(12 * 60 * 60)
    }
}
