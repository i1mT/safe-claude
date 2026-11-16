import Foundation

public enum RuleTrigger: Equatable, Sendable {
    case standard
    case elevated
    /// B08: provider trust score between 0 and 100.
    case trustScore(Int)
}

public enum ObservationStatus: Equatable, Sendable {
    case passed
    case notApplicable
    case unknown(source: String, critical: Bool)
    case unsupported(source: String, required: Bool)
    /// Equivalent evidence from the same underlying event should share the
    /// same deduplication key; independent mechanisms must use distinct keys.
    case triggered(RuleTrigger, deduplicationKey: String?)
    /// A risk signal was observed, but the same rule still has an unresolved
    /// required sub-signal. Score the observed risk and keep the assessment on
    /// hold until the missing evidence is collected.
    case triggeredAndUnknown(RuleTrigger, deduplicationKey: String?, source: String, critical: Bool)
}

public struct RuleObservation: Equatable, Sendable {
    public let id: String
    public let status: ObservationStatus
    /// Time of the underlying observation, when the collector can establish it.
    /// This is intentionally nil for unavailable or unimplemented collectors.
    public let observedAt: Date?

    public init(id: String, status: ObservationStatus, observedAt: Date? = nil) {
        self.id = id
        self.status = status
        self.observedAt = observedAt
    }
}

public struct Deduction: Equatable, Sendable {
    public let ruleID: String
    public let points: Int
    public let deduplicationKey: String
}

public struct RuleReportStatus: Codable, Equatable, Sendable {
    public let rule: String
    public let status: String
    public let points: Int
    public let source: String?
    public let observedAt: Date?
    public let remediation: String?

    public init(rule: String, status: String, points: Int = 0, source: String? = nil,
                observedAt: Date? = nil, remediation: String? = nil) {
        self.rule = rule
        self.status = status
        self.points = points
        self.source = source
        self.observedAt = observedAt
        self.remediation = remediation
    }
}

public enum SafetyDecision: String, Codable, Sendable {
    case allow, warning, hold, deny
}

public struct SafetyEvaluation: Equatable, Sendable {
    /// Present only when all required observations are complete and valid.
    public let safetyScore: Int?
    public let scoreUpperBound: Int
    public let decision: SafetyDecision
    public let deductions: [Deduction]
    public let missingRuleIDs: [String]
    public let unknownRuleIDs: [String]
    public let unsupportedRuleIDs: [String]
    public let validationErrors: [String]
    public let ruleStatuses: [RuleReportStatus]
}

/// The rule catalogue is deliberately explicit. No absent rule is equivalent to
/// a passed check; collectors must report every rule's applicability and state.
public enum SafetyRuleCatalog {
    private static let groups: [(String, [Int])] = [
        ("A", [100, 40, 35, 25, 10, 1, 30, 25, 20, 15]),
        ("B", [35, 30, 18, 6, 8, 10, 10, 0]),
        ("C", [20, 25, 12, 8, 10, 12, 10, 8]),
        ("D", [12, 6, 4, 8, 35, 25, 15, 5]),
        ("E", [6, 4, 3, 3, 2, 3, 6, 2, 3, 6]),
        ("F", [8, 10, 15, 20, 25, 15, 15, 8]),
        ("G", [8, 6, 10, 15, 6, 2, 1, 8]),
        ("H", [20, 5, 10, 3]),
    ]
    public static let weights: [String: Int] = {
        var result: [String: Int] = [:]
        for (prefix, weights) in groups {
            for (offset, weight) in weights.enumerated() {
                result[String(format: "%@%02d", prefix, offset + 1)] = weight
            }
        }
        return result
    }()
    public static let ids: [String] = weights.keys.sorted()

    fileprivate static let elevatedWeights: [String: Int] = [
        "A06": 35, "D08": 20, "E07": 15, "G01": 16, "G02": 15, "G07": 2,
    ]
}

public enum SafetyEvaluator {
    public static func evaluate(
        _ observations: [RuleObservation],
        minimumScore: Int = 80,
        warningScore: Int = 90
    ) -> SafetyEvaluation {
        var errors: [String] = []
        if !(0...100).contains(minimumScore) || !(minimumScore...100).contains(warningScore) {
            errors.append("INVALID_THRESHOLDS")
        }
        var seen = Set<String>()
        var unknownIDs: [String] = []
        var unsupportedIDs: [String] = []
        var criticalSources = Set<String>()
        var auxiliarySources = Set<String>()
        var candidates: [Deduction] = []
        var hardBlock = false
        var forcedHold = false

        for observation in observations {
            guard let base = SafetyRuleCatalog.weights[observation.id] else {
                errors.append("UNKNOWN_RULE:\(observation.id)")
                continue
            }
            guard seen.insert(observation.id).inserted else {
                errors.append("DUPLICATE_RULE:\(observation.id)")
                continue
            }
            switch observation.status {
            case .passed, .notApplicable:
                break
            case .unknown(let source, let critical):
                unknownIDs.append(observation.id)
                if source.isEmpty {
                    errors.append("EMPTY_SOURCE:\(observation.id)")
                } else if critical {
                    criticalSources.insert(source)
                } else {
                    auxiliarySources.insert(source)
                }
            case .triggeredAndUnknown(let trigger, let key, let source, let critical):
                unknownIDs.append(observation.id)
                if source.isEmpty {
                    errors.append("EMPTY_SOURCE:\(observation.id)")
                } else if critical {
                    criticalSources.insert(source)
                } else {
                    auxiliarySources.insert(source)
                }
                recordTrigger(observation.id, trigger, key, base: base)
            case .unsupported(let source, let required):
                unsupportedIDs.append(observation.id)
                if required {
                    if source.isEmpty {
                        errors.append("EMPTY_SOURCE:\(observation.id)")
                    } else {
                        criticalSources.insert(source)
                    }
                }
            case .triggered(let trigger, let key):
                recordTrigger(observation.id, trigger, key, base: base)
            }
        }
        func recordTrigger(_ ruleID: String, _ trigger: RuleTrigger, _ key: String?, base: Int) {
                // H01 and H02 are derived here, not trusted from collectors.
                guard ruleID != "H01", ruleID != "H02" else {
                    errors.append("DERIVED_RULE:\(ruleID)")
                    return
                }
                let points: Int?
                switch trigger {
                case .standard:
                    // B08 requires a measured provider score; its zero
                    // catalogue placeholder must never become a free pass.
                    points = ruleID == "B08" ? nil : base
                case .elevated:
                    points = SafetyRuleCatalog.elevatedWeights[ruleID]
                case .trustScore(let trust):
                    points = ruleID == "B08" && (0...100).contains(trust)
                        ? Int((Double(100 - trust) * 0.2).rounded()) : nil
                }
                guard let points, points >= 0 else {
                    errors.append("INVALID_TRIGGER:\(ruleID)")
                    return
                }
                if let key, key.isEmpty {
                    errors.append("EMPTY_DEDUPLICATION_KEY:\(ruleID)")
                    return
                }
                candidates.append(Deduction(ruleID: ruleID, points: points,
                                            deduplicationKey: key ?? "rule:\(ruleID)"))
                if ruleID == "A01" { hardBlock = true }
                if ["A10", "D06", "F03", "F04", "F06", "F07", "H03"].contains(ruleID) {
                    forcedHold = true
                }
        }
        let missing = SafetyRuleCatalog.ids.filter { !seen.contains($0) }
        if !missing.isEmpty { criticalSources.insert("missing-rule-observations") }
        for source in criticalSources.sorted() {
            candidates.append(Deduction(ruleID: "H01", points: 20, deduplicationKey: "critical:\(source)"))
        }
        if !auxiliarySources.isEmpty {
            candidates.append(Deduction(ruleID: "H02", points: min(15, auxiliarySources.count * 5),
                                        deduplicationKey: "auxiliary-sources"))
        }

        // An event key alone cannot merge distinct mechanisms. Only the
        // catalogue's explicitly related rules share a deduplication group.
        func group(_ id: String, _ key: String) -> String {
            if key.hasPrefix("event:") && ["C01", "C02", "C03", "C04", "C05", "C06"].contains(id) { return "exit-change" }
            if key.hasPrefix("field:") && ["E04", "E05"].contains(id) { return "process-locale" }
            if key.hasPrefix("field:") && ["B03", "B06"].contains(id) { return "proxy-classification" }
            if key.hasPrefix("event:") && ["A03", "F02"].contains(id) { return "path-change" }
            return id
        }
        var unique: [String: Deduction] = [:]
        for candidate in candidates {
            let key = group(candidate.ruleID, candidate.deduplicationKey) + "\u{0}" + candidate.deduplicationKey
            if let existing = unique[key] {
                if candidate.points > existing.points ||
                    (candidate.points == existing.points && candidate.ruleID < existing.ruleID) {
                    unique[key] = candidate
                }
            } else {
                unique[key] = candidate
            }
        }
        // Aggregate deductions only replace labels explicitly declared by the
        // source adapter. A provider name by itself proves no coverage.
        for aggregate in unique.values.filter({ $0.ruleID == "B08" }) {
            let pieces = aggregate.deduplicationKey.components(separatedBy: "|covers:")
            guard pieces.count == 2, pieces[0].hasPrefix("provider:"), pieces[0].count > 9 else { continue }
            let covered = Set(pieces[1].split(separator: ",").map(String.init))
            let allowed = Set(["B01", "B02", "B03", "B04", "B05", "B06", "B07"])
            guard !covered.isEmpty, covered.isSubset(of: allowed) else { continue }
            let related = unique.filter { _, deduction in
                deduction.deduplicationKey == pieces[0] && covered.contains(deduction.ruleID)
            }
            guard !related.isEmpty else { continue }
            if related.values.reduce(0, { $0 + $1.points }) >= aggregate.points {
                unique.removeValue(forKey: group("B08", aggregate.deduplicationKey) + "\u{0}" + aggregate.deduplicationKey)
            } else {
                for key in related.keys { unique.removeValue(forKey: key) }
            }
        }
        let deductions = unique.values.sorted {
            if $0.ruleID != $1.ruleID { return $0.ruleID < $1.ruleID }
            return $0.deduplicationKey < $1.deduplicationKey
        }
        let pointTotals = Dictionary(grouping: deductions, by: \.ruleID)
            .mapValues { $0.reduce(0) { $0 + $1.points } }
        var statusByID: [String: RuleReportStatus] = [:]
        for observation in observations where statusByID[observation.id] == nil {
            let status: String
            let source: String?
            switch observation.status {
            case .passed: status = "passed"; source = nil
            case .notApplicable: status = "notApplicable"; source = nil
            case .unknown(let value, _): status = "unknown"; source = reportableSource(value)
            case .unsupported(let value, _): status = "unsupported"; source = reportableSource(value)
            case .triggered: status = "triggered"; source = nil
            case .triggeredAndUnknown(_, _, let value, _):
                status = "triggeredUnknown"; source = reportableSource(value)
            }
            statusByID[observation.id] = RuleReportStatus(
                rule: observation.id, status: status, points: pointTotals[observation.id] ?? 0,
                source: source, observedAt: observation.observedAt,
                remediation: RuleLabels.remediation[observation.id]
            )
        }
        for id in missing where statusByID[id] == nil {
            statusByID[id] = RuleReportStatus(
                rule: id, status: "missing", remediation: RuleLabels.remediation[id]
            )
        }
        let ruleStatuses = statusByID.values.sorted { $0.rule < $1.rule }
        let score = max(0, 100 - deductions.reduce(0) { $0 + $1.points })
        let incomplete = !missing.isEmpty || !unknownIDs.isEmpty ||
            !criticalSources.isEmpty || !auxiliarySources.isEmpty || !errors.isEmpty
        let decision: SafetyDecision
        if hardBlock {
            decision = .deny
        } else if incomplete || forcedHold {
            decision = .hold
        } else if score < minimumScore {
            decision = .deny
        } else if score < warningScore {
            decision = .warning
        } else {
            decision = .allow
        }
        return SafetyEvaluation(
            safetyScore: incomplete ? nil : score,
            scoreUpperBound: score,
            decision: decision,
            deductions: deductions,
            missingRuleIDs: missing,
            unknownRuleIDs: unknownIDs.sorted(),
            unsupportedRuleIDs: unsupportedIDs.sorted(),
            validationErrors: errors.sorted(),
            ruleStatuses: ruleStatuses
        )
    }

    /// Only fixed collector identifiers cross IPC; never forward arbitrary
    /// strings that could later contain paths, hostnames, or user data.
    private static func reportableSource(_ value: String) -> String? {
        let fixed: Set<String> = [
            "stale-snapshot", "reputation", "claude-settings-locale", "history",
            "proxy-sharing", "region-policy", "reputation-location", "country-languages",
            "region", "proxycheck", "history-country-baseline", "history-country",
            "ipapi-is", "ipapi-is-open-proxy-only", "ipapi-is-unavailable",
            "proxycheck-attack-history",
            "history-asn", "history-geolocation-window", "geolocation-accuracy-unreported",
            "https-clock-stale", "https-clock-boundary",
            "tls-options-unreadable",
            "target-route", "process-time-zone", "runtime-time-zone-inheritance",
            "process-locale", "claude-settings-language",
            "auto-memory-settings", "auto-memory-index",
            "stun-country",
            "auth-context", "model-lifecycle", "dns-path-unobserved",
            "dns-resolver-geolocation", "dns-encryption-policy",
            "trust-config-unreadable",
            "network-time-status-privileged",
            "runtime-virtualization",
            "proxycheck-p2p-unobserved",
            "proxy-connectivity-unverified",
            "client-certificate-unverified",
        ]
        if fixed.contains(value) { return value }
        if value.hasPrefix("collector-gap-") {
            let rule = String(value.dropFirst("collector-gap-".count))
            if SafetyRuleCatalog.weights[rule] != nil { return value }
        }
        if value.count == 9, value.hasPrefix("adapter-"),
           let group = value.last, ("A"..."H").contains(String(group)) {
            return value
        }
        return nil
    }
}
