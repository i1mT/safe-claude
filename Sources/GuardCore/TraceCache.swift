import CryptoKit
import Foundation

/// Cache and coalesce only equal launch environments within one network epoch.
/// Sensitive proxy values are used transiently to compute a keyed digest.
actor TraceCache {
    static let shared = TraceCache()
    private let key = SymmetricKey(size: .bits256)
    private let probe: @Sendable (ClaudeTraceTarget, [String: String], [String: String], IPFamily) async -> TimedTrace
    private var cache: [Data: TimedTrace] = [:]
    private var inflight: [Data: Task<TimedTrace, Never>] = [:]
    init(probe: @escaping @Sendable (ClaudeTraceTarget, [String: String], [String: String], IPFamily) async -> TimedTrace = { target, environment, settingsEnvironment, family in
        await Task.detached {
            let result = TraceProbe.observe(target, environment: environment,
                                            settingsEnvironment: settingsEnvironment, family: family)
            return TimedTrace(result: result, observedAt: Date())
        }.value
    }) { self.probe = probe }
    func observe(target: ClaudeTraceTarget, environment: [String: String], epoch: Int,
                 fingerprint: Data, settingsEnvironment: [String: String] = [:],
                 family: IPFamily = .automatic) async -> TimedTrace {
        let envelope: [String: Any] = ["target": target.rawValue, "epoch": epoch,
                                       "family": family.rawValue,
                                       "fingerprint": fingerprint.base64EncodedString(), "environment": environment,
                                       "settingsEnvironment": settingsEnvironment]
        guard let encoded = try? JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys]) else {
            return TimedTrace(result: .unknown(reason: "CONTEXT_INVALID"), observedAt: Date())
        }
        let id = Data(HMAC<SHA256>.authenticationCode(for: encoded, using: key))
        if let item = cache[id], (0..<5).contains(Date().timeIntervalSince(item.observedAt)) { return item }
        if let task = inflight[id] { return await task.value }
        let probe = self.probe
        let task = Task.detached { await probe(target, environment, settingsEnvironment, family) }
        inflight[id] = task
        let result = await task.value
        inflight[id] = nil
        if case .observed = result.result {
            cache[id] = result
            if cache.count > 256, let oldest = cache.min(by: { $0.value.observedAt < $1.value.observedAt })?.key {
                cache.removeValue(forKey: oldest)
            }
        }
        return result
    }
}
