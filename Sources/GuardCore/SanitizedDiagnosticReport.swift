import Foundation

public struct SanitizedDiagnosticRule: Codable, Equatable, Sendable {
    public let id: String
    public let status: String
    public let points: Int
    public let observedAt: Date?
}

/// A deliberately narrow support artifact. It contains no source strings,
/// remediation text, process/session identity, ticket, or free-form reason.
public struct SanitizedDiagnosticReport: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let generatedAt: Date
    public let appVersion: String
    public let operatingSystem: String
    public let context: String?
    public let decision: String
    public let safetyScore: Int?
    public let scoreUpperBound: Int?
    public let unknownCount: Int
    public let findings: [SanitizedDiagnosticRule]
    public let rules: [SanitizedDiagnosticRule]

    public init(response: GuardResponse, appVersion: String, operatingSystem: String,
                generatedAt: Date = Date()) {
        schemaVersion = 1
        self.generatedAt = generatedAt
        self.appVersion = Self.safeVersion(appVersion)
        self.operatingSystem = Self.safeVersion(operatingSystem)
        context = response.assessmentContext?.rawValue
        decision = SafetyDecision(rawValue: response.decision)?.rawValue ?? SafetyDecision.hold.rawValue
        safetyScore = Self.safeScore(response.safetyScore)
        scoreUpperBound = Self.safeScore(response.scoreUpperBound)
        unknownCount = min(SafetyRuleCatalog.ids.count, max(0, response.unknownCount))

        findings = response.findings
            .filter { SafetyRuleCatalog.weights[$0.rule] != nil }
            .map {
                SanitizedDiagnosticRule(id: $0.rule, status: "triggered",
                                        points: Self.safePoints($0.points), observedAt: nil)
            }
            .sorted { $0.id < $1.id }

        let allowedStatuses: Set<String> = [
            "passed", "notApplicable", "unknown", "unsupported",
            "triggered", "triggeredUnknown", "missing",
        ]
        var seen = Set<String>()
        rules = (response.ruleStatuses ?? [])
            .filter {
                SafetyRuleCatalog.weights[$0.rule] != nil &&
                allowedStatuses.contains($0.status) &&
                seen.insert($0.rule).inserted
            }
            .map {
                SanitizedDiagnosticRule(id: $0.rule, status: $0.status,
                                        points: Self.safePoints($0.points),
                                        observedAt: $0.observedAt)
            }
            .sorted { $0.id < $1.id }
    }

    private static func safeVersion(_ value: String) -> String {
        let allowed = value.filter { $0.isNumber || $0 == "." || $0 == "-" }
        return String(allowed.prefix(32))
    }

    private static func safeScore(_ value: Int?) -> Int? {
        guard let value, (0...100).contains(value) else { return nil }
        return value
    }

    private static func safePoints(_ value: Int) -> Int {
        min(100, max(0, value))
    }
}
