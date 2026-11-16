import Foundation
import CryptoKit

/// Short-lived, memory-only provider cache. Entries are bound to address and
/// key; a cached result retains its original observation time.
actor ProxyCheckCache {
    static let shared = ProxyCheckCache()
    private struct Entry {
        let value: ProxyCheckObservation
        let observedAt: Date
    }
    private let cacheKey = SymmetricKey(size: .bits256)
    private var entries: [Data: Entry] = [:]
    private var inflight: [Data: Task<(ProxyCheckObservation?, Date?), Never>] = [:]
    private var retryAfter: [Data: Date] = [:]
    func observe(ip: String, apiKey: String?, environment: [String: String],
                 settingsEnvironment: [String: String] = [:]) async -> (ProxyCheckObservation?, Date?) {
        guard let cacheID = RouteBoundCacheIdentity.make(ip: ip, apiKey: apiKey, environment: environment,
            settings: settingsEnvironment, using: cacheKey) else {
            return (nil, nil)
        }
        if let entry = entries[cacheID],
           (0..<ProxyCheckV3.maximumResultAge).contains(Date().timeIntervalSince(entry.observedAt)) {
            return (entry.value, entry.observedAt)
        }
        // A single request per IP at a time. Different keys do not share a request.
        if let until = retryAfter[cacheID], until > Date() { return (nil, nil) }
        if let task = inflight[cacheID] { return await task.value }
        let task = Task.detached { () -> (ProxyCheckObservation?, Date?) in
            let value = try? await ProxyCheckV3.fetch(ip: ip, routingEnvironment: environment,
                                                     apiKey: apiKey, settingsEnvironment: settingsEnvironment)
            return (value, value == nil ? nil : Date())
        }
        inflight[cacheID] = task
        let result = await task.value
        inflight[cacheID] = nil
        if let value = result.0, let date = result.1, !value.warning {
            retryAfter[cacheID] = nil
            entries[cacheID] = Entry(value: value, observedAt: date)
            if entries.count > 128 {
                let oldest = entries.min { $0.value.observedAt < $1.value.observedAt }?.key
                if let oldest { entries.removeValue(forKey: oldest) }
            }
        } else {
            retryAfter[cacheID] = Date().addingTimeInterval(apiKey == nil
                ? ProxyCheckV3.maximumResultAge : 60)
            if retryAfter.count > 128, let oldest = retryAfter.min(by: { $0.value < $1.value })?.key {
                retryAfter.removeValue(forKey: oldest)
            }
        }
        return result
    }
}
