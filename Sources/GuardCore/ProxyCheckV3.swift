import Foundation

/// Sensitive IPs are held only in memory; callers must not log observations.
public struct ProxyCheckObservation: Equatable, Sendable {
    public let ip: String
    public let isProxy: Bool?
    public let isVPN: Bool?
    public let isTor: Bool?
    public let isHosting: Bool?
    public let isAnonymous: Bool?
    /// ProxyCheck estimates, not observed device counts. Null/malformed values
    /// remain unavailable and must not be interpreted as a low-sharing result.
    public let estimatedDevicesAtAddress: Int?
    public let estimatedDevicesInSubnet: Int?
    /// Provider database refresh time, distinct from the time this response
    /// was fetched. Missing or malformed values leave freshness unknown.
    public let sourceDataUpdatedAt: Date?
    /// The documented operator metadata lists residential proxy services
    /// offered by the network operator; it does not prove this IP is a proxy
    /// endpoint, so the product treats it as a conservative association signal.
    public let operatorOffersResidentialProxies: Bool?
    public let risk: Int?
    public let hasAttacks: Bool?
    public let warning: Bool
}

/// Adapter for proxycheck.io v3, API schema 24-June-2026.
public enum ProxyCheckV3 {
    /// ProxyCheck recommends at most 15 minutes for anonymous IP results.
    /// SafeClaude applies that conservative ceiling to all cached v3 results.
    public static let maximumResultAge: TimeInterval = 900

    /// Product heuristic: ProxyCheck documents the estimate but does not
    /// publish a risk threshold. Counts at/above this value are scored as a
    /// high-sharing warning while B07 remains unresolved for P2P coverage.
    public static let highAddressDeviceEstimateThreshold = 25

    public static func request(ip: String, apiKey: String? = nil) throws -> URL {
        guard IPAddress.bytes(ip) != nil else { throw ReputationError.invalidAddress }
        if let apiKey {
            guard (1...128).contains(apiKey.utf8.count),
                  apiKey.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) ||
                      (97...122).contains($0) || $0 == 45 }) else {
                throw ReputationError.requestFailed
            }
        }
        var components = URLComponents(string: "https://proxycheck.io/v3/")!
        components.path += ip
        components.percentEncodedQuery =
            "tag=0&risk=2&days=30&ver=24-June-2026" + (apiKey.map { "&key=" + $0 } ?? "")
        guard let url = components.url else { throw ReputationError.invalidAddress }
        return url
    }

    public static func fetch(ip: String, routingEnvironment: [String: String], apiKey: String? = nil,
                             settingsEnvironment: [String: String] = [:]) async throws -> ProxyCheckObservation {
        let data = try GeolocationTransport.get(url: request(ip: ip, apiKey: apiKey), environment: routingEnvironment,
                                                settings: settingsEnvironment)
        return try decode(data, expectedIP: ip)
    }

    public static func decode(_ data: Data, expectedIP: String) throws -> ProxyCheckObservation {
        guard IPAddress.bytes(expectedIP) != nil else { throw ReputationError.invalidAddress }
        guard data.count <= 65_536,
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let status = root["status"] as? String, ["ok", "warning"].contains(status),
              let row = root[expectedIP] as? [String: Any],
              let detection = row["detections"] as? [String: Any] else {
            throw ReputationError.malformedResponse
        }
        func boolean(_ key: String) -> Bool? {
            guard let n = detection[key] as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }
            return n.boolValue
        }
        var risk: Int?
        if let number = detection["risk"] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
           number.doubleValue.rounded() == number.doubleValue, (0...100).contains(number.doubleValue) {
            risk = number.intValue
        }
        // An explicit positive association can be scored, but a negative or
        // missing services list cannot rule out a P2P proxy classification.
        let operatorOffersResidentialProxies: Bool? = {
            guard let operatorInfo = row["operator"] as? [String: Any],
                  let services = operatorInfo["services"] as? [Any],
                  services.count <= 64 else { return nil }
            guard services.allSatisfy({ value in
                guard let service = value as? String else { return false }
                return service.utf8.count <= 128 && !service.utf8.contains(0)
            }) else {
                return nil
            }
            return services.contains { ($0 as? String) == "residential_proxies" }
        }()
        // The request pins a 30-day window. Missing, null, malformed, or
        // overlarge history is unknown; only a complete count map can establish
        // either positive activity or a clean window.
        let attacks: Bool? = {
            guard let history = row["attack_history"] as? [String: Any],
                  history.count <= 64 else { return nil }
            var foundAttack = false
            for (category, rawCount) in history {
                guard !category.isEmpty, category.utf8.count <= 128,
                      category.utf8.allSatisfy({
                          (48...57).contains($0) || (65...90).contains($0) ||
                          (97...122).contains($0) || $0 == 45 || $0 == 95
                      }),
                      let number = rawCount as? NSNumber,
                      CFGetTypeID(number) != CFBooleanGetTypeID(),
                      number.doubleValue.rounded() == number.doubleValue,
                      (0...1_000_000).contains(number.intValue) else { return nil }
                foundAttack = foundAttack || number.intValue > 0
            }
            return foundAttack
        }()
        let deviceEstimate = row["device_estimate"] as? [String: Any]
        func deviceCount(_ key: String) -> Int? {
            guard let number = deviceEstimate?[key] as? NSNumber,
                  CFGetTypeID(number) != CFBooleanGetTypeID(),
                  number.doubleValue.rounded() == number.doubleValue,
                  (0...1_000_000_000).contains(number.doubleValue) else { return nil }
            return number.intValue
        }
        let sourceDataUpdatedAt: Date? = {
            guard let raw = row["last_updated"] as? String,
                  raw.utf8.count <= 40 else { return nil }
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = formatter.date(from: raw) { return date }
            formatter.formatOptions = [.withInternetDateTime]
            return formatter.date(from: raw)
        }()
        return ProxyCheckObservation(ip: expectedIP, isProxy: boolean("proxy"), isVPN: boolean("vpn"),
                                     isTor: boolean("tor"), isHosting: boolean("hosting"),
                                     isAnonymous: boolean("anonymous"),
                                     estimatedDevicesAtAddress: deviceCount("address"),
                                     estimatedDevicesInSubnet: deviceCount("subnet"),
                                     sourceDataUpdatedAt: sourceDataUpdatedAt,
                                     operatorOffersResidentialProxies: operatorOffersResidentialProxies,
                                     risk: risk, hasAttacks: attacks, warning: status == "warning")
    }
}
