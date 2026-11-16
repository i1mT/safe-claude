import Foundation

/// Builds the peer requirement used by the privileged network-time XPC listener.
public enum NetworkTimeServiceRequirement {
    public static func make(bundleIdentifier: String, teamIdentifier: String) -> String? {
        let bundlePattern = #"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"#
        let teamPattern = #"^[A-Z0-9]{10}$"#
        guard bundleIdentifier.range(of: bundlePattern, options: .regularExpression) != nil,
              teamIdentifier.range(of: teamPattern, options: .regularExpression) != nil else {
            return nil
        }
        return "anchor apple generic and identifier \"\(bundleIdentifier)\" " +
            "and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    }
}
