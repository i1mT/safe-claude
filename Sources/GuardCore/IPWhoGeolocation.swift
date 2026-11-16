import Foundation

/// Free IPWho geolocation has no security labels; it must be combined with a
/// separate reputation source rather than treating absent labels as negative.
public enum IPWhoGeolocation {
    public static func request(ip: String) throws -> URLRequest {
        guard IPAddress.bytes(ip) != nil else { throw ReputationError.invalidAddress }
        let base = URL(string: "https://ipwho.is/")!
        var request = URLRequest(url: base.appendingPathComponent(ip),
                                 cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                                 timeoutInterval: 2)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    /// Fetch only after explicit opt-in to sending the observed address to IPWho.
    /// The same proxy and bypass configuration is resolved for the lookup host.
    public static func fetch(ip: String, routingEnvironment: [String: String],
                             settingsEnvironment: [String: String] = [:]) async throws -> IPReputation {
        let url = try request(ip: ip).url!
        let data = try GeolocationTransport.get(url: url, environment: routingEnvironment, settings: settingsEnvironment)
        return try decode(data, expectedIP: ip)
    }

    public static func decode(_ data: Data, expectedIP: String) throws -> IPReputation {
        guard let expected = IPAddress.bytes(expectedIP) else { throw ReputationError.invalidAddress }
        guard data.count <= 65_536,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let success = object["success"] as? NSNumber,
              CFGetTypeID(success) == CFBooleanGetTypeID(), success.boolValue,
              let ip = object["ip"] as? String, let actual = IPAddress.bytes(ip) else {
            throw ReputationError.malformedResponse
        }
        guard actual == expected else { throw ReputationError.mismatchedAddress }
        let countryValue = (object["country_code"] as? String)?.uppercased()
        let country = countryValue.flatMap {
            $0.utf8.count == 2 && $0.utf8.allSatisfy { (65...90).contains($0) } ? $0 : nil
        }
        let zone = (object["timezone"] as? [String: Any])?["id"] as? String
        let timeZone = zone.flatMap { TimeZone(identifier: $0) == nil ? nil : $0 }
        let latitude = coordinate(object["latitude"], range: -90...90)
        let longitude = coordinate(object["longitude"], range: -180...180)
        let rawASN = (object["connection"] as? [String: Any])?["asn"] as? NSNumber
        let asn: Int?
        if let rawASN, CFGetTypeID(rawASN) != CFBooleanGetTypeID(),
           rawASN.doubleValue.rounded() == rawASN.doubleValue,
           (1...4_294_967_295).contains(rawASN.doubleValue) {
            asn = rawASN.intValue
        } else {
            asn = nil
        }
        return IPReputation(ip: ip, countryCode: country, timeZone: timeZone,
                            latitude: latitude, longitude: longitude,
                            autonomousSystem: asn, isDatacenter: nil, isVPN: nil,
                            isProxy: nil, isTor: nil, isAbuser: nil)
    }

    private static func coordinate(_ value: Any?, range: ClosedRange<Double>) -> Double? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let coordinate = number.doubleValue
        return coordinate.isFinite && range.contains(coordinate) ? coordinate : nil
    }
}
