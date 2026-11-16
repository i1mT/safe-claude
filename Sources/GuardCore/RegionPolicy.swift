import Foundation

/// Generated from DataSources/region-policy-2026-11-12.json.
/// Ukraine and unlisted dependent territories remain unknown pending subdivision/sovereignty data.
public enum RegionPolicy {
    public enum Result: Equatable, Sendable { case supported, unsupported, unknown }
    // Wait until the official calendar date has begun in all time zones.
    private static let starts = Date(timeIntervalSince1970: 1794484800)
    private static let expires = Date(timeIntervalSince1970: 1797033600)
    private static let supported: Set<String> = [
        "AD", "AE", "AG", "AL", "AM", "AO", "AR", "AT", "AU", "AZ", "BA", "BB",
        "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BN", "BO", "BR", "BS", "BT",
        "BW", "BZ", "CA", "CD", "CF", "CG", "CH", "CI", "CL", "CM", "CO", "CR",
        "CV", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG",
        "ER", "ES", "ET", "FI", "FJ", "FM", "FR", "GA", "GB", "GD", "GE", "GH",
        "GM", "GN", "GQ", "GR", "GT", "GW", "GY", "HN", "HR", "HT", "HU", "ID",
        "IE", "IL", "IN", "IQ", "IS", "IT", "JM", "JO", "JP", "KE", "KG", "KH",
        "KI", "KM", "KN", "KR", "KW", "KZ", "LA", "LB", "LC", "LI", "LK", "LR",
        "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MG", "MH", "MK",
        "ML", "MN", "MR", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NE",
        "NG", "NI", "NL", "NO", "NP", "NR", "NZ", "OM", "PA", "PE", "PG", "PH",
        "PK", "PL", "PR", "PS", "PT", "PW", "PY", "QA", "RO", "RS", "RW", "SA",
        "SB", "SC", "SD", "SE", "SG", "SI", "SK", "SL", "SM", "SN", "SO", "SR",
        "SS", "ST", "SV", "SZ", "TD", "TG", "TH", "TJ", "TL", "TM", "TN", "TO",
        "TR", "TT", "TV", "TW", "TZ", "UG", "US", "UY", "UZ", "VA", "VC", "VN",
        "VU", "WS", "ZA", "ZM", "ZW",
    ]
    private static let unsupported: Set<String> = ["AF", "BY", "CN", "CU", "HK", "IR", "KP", "MM", "MO", "RU", "SY", "VE", "YE"]

    public static func classify(countryCode: String, at: Date = Date()) -> Result {
        guard at >= starts && at < expires else { return .unknown }
        let code = countryCode.uppercased()
        if supported.contains(code) { return .supported }
        if unsupported.contains(code) { return .unsupported }
        return .unknown
    }
}
