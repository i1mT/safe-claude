import Foundation

public enum DNSResolverCountryResult: Sendable, Equatable {
    case notApplicable
    case matching
    case different
    case unknown
    case differentWithUnknown
}

public struct DNSResolverCountryAssessment: Sendable, Equatable {
    public let httpConsistency: DNSResolverCountryResult
    public let resolverConsistency: DNSResolverCountryResult
    public let httpObservedAt: Date?
    public let resolverObservedAt: Date?

    public static func evaluate(
        samples: [DNSResolverCountrySample],
        configuredResolverDigests: [String]?,
        observedResolverDigest: String?,
        targetHTTPCountry: String?,
        targetHTTPObservedAt: Date?,
        at time: Date = Date(),
        maximumSampleAge: TimeInterval = DNSResolverEgressCache.lifetime
    ) -> DNSResolverCountryAssessment {
        guard let configuredResolverDigests, !configuredResolverDigests.isEmpty,
              configuredResolverDigests.count <= DNSResolverEgressCache.maximumResolvers else {
            return DNSResolverCountryAssessment(httpConsistency: .unknown,
                resolverConsistency: .unknown,
                httpObservedAt: nil, resolverObservedAt: nil)
        }

        let fresh = Dictionary(samples.compactMap { sample -> (String, String)? in
            guard configuredResolverDigests.contains(sample.resolverDigest),
                  (0...maximumSampleAge).contains(time.timeIntervalSince(sample.observedAt)),
                  let country = normalizedCountry(sample.countryCode) else { return nil }
            return (sample.resolverDigest, country)
        }, uniquingKeysWith: { first, _ in first })

        let resolverResult = compareResolvers(configuredResolverDigests, fresh)
        let resolverDate = resolverObservedAt(configuredResolverDigests, samples, at: time,
            maximumAge: maximumSampleAge)
        guard (0...maximumSampleAge).contains(time.timeIntervalSince(targetHTTPObservedAt ?? .distantPast)),
              let targetCountry = normalizedCountry(targetHTTPCountry) else {
            return DNSResolverCountryAssessment(httpConsistency: .unknown,
                resolverConsistency: resolverResult, httpObservedAt: nil,
                resolverObservedAt: resolverDate)
        }

        let httpDigests: [String]
        if let observedResolverDigest {
            guard configuredResolverDigests.contains(observedResolverDigest) else {
                return DNSResolverCountryAssessment(httpConsistency: .unknown,
                    resolverConsistency: resolverResult, httpObservedAt: nil,
                    resolverObservedAt: resolverDate)
            }
            httpDigests = [observedResolverDigest]
        } else {
            // Before the first Claude DNS flow is observed, conservatively
            // compare every configured resolver that could serve the request.
            httpDigests = configuredResolverDigests
        }
        let knownHTTPDifferences = httpDigests.contains {
            guard let country = fresh[$0] else { return false }
            return country != targetCountry
        }
        let httpComplete = httpDigests.allSatisfy { fresh[$0] != nil }
        let httpResult: DNSResolverCountryResult = {
            if knownHTTPDifferences { return httpComplete ? .different : .differentWithUnknown }
            return httpComplete ? .matching : .unknown
        }()
        let httpDates = httpDigests.compactMap { digest in
            samples.first(where: { $0.resolverDigest == digest && fresh[digest] != nil })?.observedAt
        }
        let differenceDates = httpDigests.compactMap { digest -> Date? in
            guard fresh[digest].map({ $0 != targetCountry }) == true else { return nil }
            return samples.first(where: { $0.resolverDigest == digest })?.observedAt
        }
        return DNSResolverCountryAssessment(httpConsistency: httpResult,
            resolverConsistency: resolverResult,
            httpObservedAt: httpDates.count == httpDigests.count
                ? ([targetHTTPObservedAt!] + httpDates).min()
                : (differenceDates.isEmpty ? nil : ([targetHTTPObservedAt!] + differenceDates).min()),
            resolverObservedAt: resolverDate)
    }

    private static func compareResolvers(_ digests: [String],
                                         _ countries: [String: String]) -> DNSResolverCountryResult {
        guard !digests.isEmpty else { return .unknown }
        guard digests.count > 1 else { return .notApplicable }
        let known = digests.compactMap { countries[$0] }
        let different = Set(known).count > 1
        let complete = known.count == digests.count
        if different { return complete ? .different : .differentWithUnknown }
        return complete ? .matching : .unknown
    }

    private static func resolverObservedAt(_ digests: [String], _ samples: [DNSResolverCountrySample],
                                          at time: Date, maximumAge: TimeInterval) -> Date? {
        let dates = digests.compactMap { digest in
            samples.first(where: {
                $0.resolverDigest == digest && normalizedCountry($0.countryCode) != nil &&
                    (0...maximumAge).contains(time.timeIntervalSince($0.observedAt))
            })?.observedAt
        }
        return dates.min()
    }

    private static func normalizedCountry(_ value: String?) -> String? {
        guard let value else { return nil }
        let country = value.uppercased()
        return country.utf8.count == 2 && country.utf8.allSatisfy({ (65...90).contains($0) })
            ? country : nil
    }
}
