import Foundation

public enum Consistency: String, Codable, Sendable {
    case matching
    case different
    case unknown
    case notApplicable
}

/// Compares supplied, independently collected facts. No country or language is
/// inferred from an unverified IP; collectors must supply those inputs.
public enum EnvironmentConsistency {
    /// Compares full historical and current offset fingerprints: aliases match,
    /// while different regions sharing today's UTC offset remain distinguishable.
    /// Missing or unrecognized source zones remain unknown.
    public static func timeZone(
        local: TimeZone,
        expectedIdentifiers: [String],
        at date: Date = Date()
    ) -> Consistency {
        guard !expectedIdentifiers.isEmpty else { return .unknown }
        let zones = expectedIdentifiers.compactMap(TimeZone.init(identifier:))
        guard zones.count == expectedIdentifiers.count else { return .unknown }
        // Two samples per year since 1900 distinguish zones such as Shanghai
        // and Singapore, which both currently use UTC+8 but have distinct
        // historical transitions. Include the current season and the next one.
        let year: TimeInterval = 365.2425 * 86_400
        let start = Date(timeIntervalSince1970: -2_208_988_800)
        var dates = (0..<252).map { start.addingTimeInterval(Double($0) * year / 2) }
        dates.append(contentsOf: [date, date.addingTimeInterval(183 * 86_400)])
        let localOffsets = dates.map { local.secondsFromGMT(for: $0) }
        return zones.contains { candidate in
            dates.map { candidate.secondsFromGMT(for: $0) } == localOffsets
        } ? .matching : .different
    }

    /// A missing TZ inherits the configured system zone. An invalid explicit TZ
    /// is unknown rather than silently substituted.
    public static func processTimeZone(
        environment: [String: String],
        system: TimeZone,
        at date: Date = Date()
    ) -> Consistency {
        guard let explicit = environment["TZ"] else { return .matching }
        guard !explicit.isEmpty, let processZone = TimeZone(identifier: explicit) else { return .unknown }
        return timeZone(local: system, expectedIdentifiers: [processZone.identifier], at: date)
    }

    /// Country language sets come from a versioned data adapter, not from a
    /// single assumed national language.
    public static func language(local: String?, expectedLanguages: [String]) -> Consistency {
        guard let local, let current = languageCode(local), !expectedLanguages.isEmpty else { return .unknown }
        let expected = expectedLanguages.compactMap(languageCode)
        guard expected.count == expectedLanguages.count else { return .unknown }
        return expected.contains(current) ? .matching : .different
    }

    public static func processLanguage(
        environment: [String: String],
        preferredLanguages: [String]
    ) -> Consistency {
        guard let system = preferredLanguages.first else { return .unknown }
        let value = ["LC_ALL", "LC_MESSAGES", "LANG"].compactMap { key -> String? in
            guard let value = environment[key], !value.isEmpty else { return nil }
            return value
        }.first
        guard let value else { return .unknown }
        let normalized = value.uppercased()
        if normalized == "C" || normalized == "POSIX" || normalized.hasPrefix("C.") {
            return .notApplicable
        }
        return language(local: value, expectedLanguages: [system])
    }

    /// Compare LANG with a higher-priority explicit locale, without treating
    /// generic C/POSIX locales as a geographic or language claim.
    public static func localeOverride(environment: [String: String]) -> Consistency {
        guard let base = environment["LANG"], !base.isEmpty else { return .unknown }
        guard let override = ["LC_ALL", "LC_MESSAGES", "LC_CTYPE"].compactMap({ environment[$0] })
            .first(where: { !$0.isEmpty }) else { return .notApplicable }
        func components(_ value: String) -> (String, String?)? {
            let stripped = String(value.split(separator: ".", maxSplits: 1).first ?? "")
            if ["C", "POSIX"].contains(stripped.uppercased()) { return nil }
            let locale = Locale(identifier: stripped.replacingOccurrences(of: "_", with: "-"))
            guard let lang = locale.language.languageCode?.identifier.lowercased(), (2...3).contains(lang.count) else { return nil }
            return (lang, locale.region?.identifier.uppercased())
        }
        guard let a = components(base), let b = components(override) else { return .unknown }
        if a.0 != b.0 { return .different }
        if let aRegion = a.1, let bRegion = b.1, aRegion != bRegion { return .different }
        return .matching
    }

    private static func languageCode(_ identifier: String) -> String? {
        let stripped = identifier.split(separator: ".", maxSplits: 1).first.map(String.init) ?? identifier
        let clean = stripped.replacingOccurrences(of: "_", with: "-")
        let code = Locale(identifier: clean).language.languageCode?.identifier.lowercased()
        guard let code, (2...3).contains(code.count), code.allSatisfy(\.isLetter) else { return nil }
        return code
    }
}
