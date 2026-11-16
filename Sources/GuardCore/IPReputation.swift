import Darwin
import Foundation

public enum ReputationError: Error, Equatable {
    case invalidAddress
    case invalidAPIKey
    case malformedResponse
    case mismatchedAddress
    case requestFailed
    case routeUnverified
}

/// Missing fields stay nil; they must not be treated as a clean reputation.
public struct IPReputation: Equatable, Sendable {
    public let ip: String
    public let countryCode: String?
    public let timeZone: String?
    public let latitude: Double?
    public let longitude: Double?
    public let autonomousSystem: Int?
    public let isDatacenter: Bool?
    public let isVPN: Bool?
    public let isProxy: Bool?
    public let isTor: Bool?
    public let isAbuser: Bool?

    public init(ip: String, countryCode: String?, timeZone: String?,
                latitude: Double? = nil, longitude: Double? = nil,
                autonomousSystem: Int?, isDatacenter: Bool?, isVPN: Bool?,
                isProxy: Bool?, isTor: Bool?, isAbuser: Bool?) {
        self.ip = ip
        self.countryCode = countryCode
        self.timeZone = timeZone
        self.latitude = latitude
        self.longitude = longitude
        self.autonomousSystem = autonomousSystem
        self.isDatacenter = isDatacenter
        self.isVPN = isVPN
        self.isProxy = isProxy
        self.isTor = isTor
        self.isAbuser = isAbuser
    }
}

/// Request/response adapter only; networking, credential storage, cache and
/// authorization are deliberately separate. API keys never go into URLs.
public enum IPAPIAdapter {
    public static func makeRequest(ip: String, apiKey: String) throws -> URLRequest {
        guard IPAddress.bytes(ip) != nil else { throw ReputationError.invalidAddress }
        guard (1...256).contains(apiKey.utf8.count),
              apiKey.utf8.allSatisfy({ (33...126).contains($0) }) else {
            throw ReputationError.invalidAPIKey
        }
        let url = URL(string: "https://api.ipapi.is/")!
        var request = URLRequest(url: url, timeoutInterval: 2)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(
            withJSONObject: ["ips": [ip], "key": apiKey], options: [.sortedKeys]
        )
        return request
    }

    public static func fetch(ip: String, apiKey: String, routingEnvironment: [String: String],
                             settingsEnvironment: [String: String] = [:]) async throws -> IPReputation {
        let request = try makeRequest(ip: ip, apiKey: apiKey)
        guard let url = request.url, let body = request.httpBody else { throw ReputationError.requestFailed }
        let data = try GeolocationTransport.post(url: url, body: body, environment: routingEnvironment,
                                                 settings: settingsEnvironment)
        return try decode(data, expectedIP: ip)
    }

    public static func decode(_ data: Data, expectedIP: String) throws -> IPReputation {
        guard let expectedBytes = IPAddress.bytes(expectedIP) else { throw ReputationError.invalidAddress }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ReputationError.malformedResponse
        }
        // Bulk POST responses are keyed by address; direct single-object
        // responses are also accepted for locally saved fixtures.
        let record: [String: Any]
        if let directIP = object["ip"] as? String, IPAddress.bytes(directIP) != nil {
            record = object
        } else if let keyed = object[expectedIP] as? [String: Any] {
            record = keyed
        } else {
            throw ReputationError.malformedResponse
        }
        guard let responseIP = record["ip"] as? String,
              let responseBytes = IPAddress.bytes(responseIP) else {
            throw ReputationError.malformedResponse
        }
        guard responseBytes == expectedBytes else { throw ReputationError.mismatchedAddress }
        let location = record["location"] as? [String: Any]
        let asn = record["asn"] as? [String: Any]
        let country = (location?["country_code"] as? String)?.uppercased()
        let validCountry = country.flatMap {
            $0.utf8.count == 2 && $0.utf8.allSatisfy { (65...90).contains($0) } ? $0 : nil
        }
        let zone = (location?["timezone"] as? String).flatMap {
            TimeZone(identifier: $0) == nil ? nil : $0
        }
        let latitude = Self.coordinate(location?["latitude"], range: -90...90)
        let longitude = Self.coordinate(location?["longitude"], range: -180...180)
        return IPReputation(
            ip: responseIP,
            countryCode: validCountry,
            timeZone: zone,
            latitude: latitude,
            longitude: longitude,
            autonomousSystem: strictInteger(asn?["asn"]),
            isDatacenter: strictBoolean(record["is_datacenter"]),
            isVPN: vpnBoolean(record["is_vpn"]),
            isProxy: strictBoolean(record["is_proxy"]),
            isTor: strictBoolean(record["is_tor"]),
            isAbuser: strictBoolean(record["is_abuser"])
        )
    }

    private static func strictBoolean(_ value: Any?) -> Bool? {
        guard let value else { return nil }
        // JSONSerialization bridges numeric 0/1 and bool to NSNumber. Check
        // CF type to keep a numeric or unexpected value from becoming "safe".
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    /// The provider documents `is_vpn` as a JavaScript-truthy field, which may
    /// contain a non-boolean value. Null/missing remains unknown.
    private static func vpnBoolean(_ value: Any?) -> Bool? {
        guard let value, !(value is NSNull) else { return nil }
        if let number = value as? NSNumber { return number.doubleValue != 0 }
        if let text = value as? String { return !text.isEmpty }
        if value is [Any] || value is [String: Any] { return true }
        return nil
    }

    private static func strictInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let value = number.doubleValue
        guard value.rounded() == value, value >= 1, value <= 4_294_967_295 else { return nil }
        return Int(value)
    }

    private static func coordinate(_ value: Any?, range: ClosedRange<Double>) -> Double? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let coordinate = number.doubleValue
        return coordinate.isFinite && range.contains(coordinate) ? coordinate : nil
    }

}

enum IPAddress {
    /// Canonical binary form avoids treating equivalent IPv6 spellings as
    /// different destinations. Zone-scoped or non-IP input is rejected.
    static func bytes(_ ip: String) -> [UInt8]? {
        var ipv4 = in_addr()
        if ip.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return withUnsafeBytes(of: &ipv4) { [4] + Array($0) }
        }
        var ipv6 = in6_addr()
        if ip.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            return withUnsafeBytes(of: &ipv6) { [6] + Array($0) }
        }
        return nil
    }

    static func isPubliclyRoutable(_ ip: String) -> Bool {
        guard let bytes = bytes(ip) else { return false }
        if bytes[0] == 4 {
            let octets = Array(bytes.dropFirst())
            let a = Int(octets[0]), b = Int(octets[1]), c = Int(octets[2])
            if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
            if a == 100 && (64...127).contains(b) { return false }
            if a == 169 && b == 254 { return false }
            if a == 172 && (16...31).contains(b) { return false }
            if a == 192 && b == 168 { return false }
            if a == 192 && b == 0 && (c == 0 || c == 2) { return false }
            if a == 192 && b == 88 && c == 99 { return false }
            if a == 198 && (18...19).contains(b) { return false }
            if a == 198 && b == 51 && c == 100 { return false }
            if a == 203 && b == 0 && c == 113 { return false }
            return true
        }
        let octets = Array(bytes.dropFirst())
        guard octets.count == 16 else { return false }
        if octets.prefix(12).elementsEqual([UInt8](repeating: 0, count: 10) + [0xff, 0xff]) {
            let mapped = octets.suffix(4)
            let text = mapped.map(String.init).joined(separator: ".")
            return isPubliclyRoutable(text)
        }
        guard octets[0] & 0xe0 == 0x20 else { return false } // 2000::/3 global unicast
        if octets[0] == 0x20 && octets[1] == 0x01 {
            if octets[2] == 0x0d && octets[3] == 0xb8 { return false } // documentation
            if octets[2] == 0x00 && octets[3] == 0x00 { return false } // Teredo
            if octets[2] == 0x00 && octets[3] == 0x02 { return false } // benchmarking
        }
        if octets[0] == 0x20 && octets[1] == 0x02 { return false } // 6to4
        return true
    }
}
