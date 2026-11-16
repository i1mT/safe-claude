import CryptoKit
import Foundation

/// An individual launch and its runtime monitor share this in-memory baseline.
/// Addresses never leave the actor and are represented only by keyed digests.
public actor SessionExitTracker {
    public struct Observation: Sendable {
        public let changed: Bool
        public let eventKey: String?
    }
    private let key = SymmetricKey(size: .bits256)
    private var baseline: Data?
    private var last: Data?
    private var lastEvent: String?

    public init() {}

    private func addressDigest(_ ip: String) -> Data? {
        guard let bytes = IPAddress.bytes(ip) else { return nil }
        // A session baseline refers to the exact approved exit; /64
        // aggregation is limited to the historical churn rule C04.
        return Data(HMAC<SHA256>.authenticationCode(for: bytes, using: key))
    }
    public func differsFromBaseline(ip: String) -> Bool? {
        guard let baseline, let digest = addressDigest(ip) else { return nil }
        return digest != baseline
    }
    public func observe(ip: String, at: Date) -> Observation? {
        guard let digest = addressDigest(ip) else { return nil }
        if baseline == nil {
            baseline = digest
            last = digest
            return Observation(changed: false, eventKey: nil)
        }
        if digest != last {
            lastEvent = "event:history-\(at.timeIntervalSince1970)"
            last = digest
        }
        return Observation(changed: digest != baseline, eventKey: digest == baseline ? nil : lastEvent)
    }
}
