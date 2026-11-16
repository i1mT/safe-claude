import Foundation

/// Minimized protocol and scope facts copied from the active system DNS
/// settings. Resolver addresses and provider URLs are intentionally omitted.
public struct DNSResolverPolicySetting: Sendable, Equatable {
    public let security: DNSPathEvidence.ResolverSecurity
    public let matchDomains: [String]?

    public init(security: DNSPathEvidence.ResolverSecurity, matchDomains: [String]?) {
        self.security = security
        self.matchDomains = matchDomains?.map { $0.lowercased() }
    }
}

public enum DNSResolverPolicy {
    /// Returns one settings index only when every requested name resolves
    /// through the same uniquely applicable resolver configuration.
    public static func uniqueApplicableSettingIndex(
        for queryNames: [String],
        settings: [DNSResolverPolicySetting]?
    ) -> Int? {
        guard let settings, !settings.isEmpty, !queryNames.isEmpty else { return nil }
        var selected: Int?
        for rawName in queryNames {
            let name = rawName.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            guard !name.isEmpty else { return nil }
            let applicable = settings.indices.filter { index in
                guard let domains = settings[index].matchDomains else { return true }
                guard !domains.isEmpty else { return false }
                return domains.contains { rawDomain in
                    let domain = rawDomain.trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    return !domain.isEmpty && (name == domain || name.hasSuffix("." + domain))
                }
            }
            guard applicable.count == 1, let index = applicable.first else { return nil }
            if let selected, selected != index { return nil }
            selected = index
        }
        return selected
    }

    /// Returns a security level only when each query name resolves to exactly
    /// one unambiguous active setting and all names use the same protocol.
    public static func security(
        for queryNames: [String],
        settings: [DNSResolverPolicySetting]?
    ) -> DNSPathEvidence.ResolverSecurity {
        guard let settings, !settings.isEmpty, !queryNames.isEmpty else { return .unknown }
        var observed = Set<DNSPathEvidence.ResolverSecurity>()

        for rawName in queryNames {
            let name = rawName.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            guard !name.isEmpty else { return .unknown }
            var applicable: [DNSPathEvidence.ResolverSecurity] = []
            for setting in settings {
                guard let domains = setting.matchDomains else {
                    applicable.append(setting.security)
                    continue
                }
                guard !domains.isEmpty else { return .unknown }
                if domains.contains(where: { rawDomain in
                    let domain = rawDomain.trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    return domain.isEmpty || name == domain || name.hasSuffix("." + domain)
                }) {
                    applicable.append(setting.security)
                }
            }
            guard applicable.count == 1, let security = applicable.first,
                  security != .unknown else { return .unknown }
            observed.insert(security)
        }
        return observed.count == 1 ? observed.first! : .unknown
    }
}
