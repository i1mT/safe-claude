import Foundation
import SystemConfiguration

/// Environment-only network probes cannot reproduce a system proxy or PAC.
public enum SystemProxyState: Equatable, Sendable {
    case inactive, configured, unknown

    public static func current() -> SystemProxyState {
        guard let dictionary = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return .unknown }
        return evaluate(dictionary)
    }

    static func evaluate(_ values: [String: Any]) -> SystemProxyState {
        for key in ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"] {
            guard let raw = values[key] else { continue }
            guard let value = raw as? NSNumber else { return .unknown }
            guard value.doubleValue == 0 || value.doubleValue == 1 else { return .unknown }
            if value.doubleValue == 1 { return .configured }
        }
        if let scopedValue = values["__SCOPED__"] {
            guard let scoped = scopedValue as? [String: Any] else { return .unknown }
            for entry in scoped.values where !(entry is [String: Any]) { return .unknown }
        }
        for value in values.values {
            if let scoped = value as? [String: Any] {
                let result = evaluate(scoped)
                if result != .inactive { return result }
            }
        }
        return .inactive
    }
}
