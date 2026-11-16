import Foundation
import CryptoKit

actor IPWhoCache {
    static let shared = IPWhoCache()
    private struct Entry { let value: IPReputation; let observedAt: Date }
    private let cacheKey = SymmetricKey(size: .bits256)
    private var entries: [Data: Entry] = [:]
    private var inflight: [Data: Task<(IPReputation?, Date?), Never>] = [:]
    private var retryAfter: [Data: Date] = [:]
    func observe(ip: String, environment: [String: String],
                 settingsEnvironment: [String: String] = [:]) async -> (IPReputation?, Date?) {
        guard let cacheID = RouteBoundCacheIdentity.make(ip: ip, environment: environment,
            settings: settingsEnvironment, using: cacheKey) else {
            return (nil, nil)
        }
        if let entry = entries[cacheID], (0..<21_600).contains(Date().timeIntervalSince(entry.observedAt)) {
            return (entry.value, entry.observedAt)
        }
        if let until = retryAfter[cacheID], until > Date() { return (nil, nil) }
        if let task = inflight[cacheID] { return await task.value }
        let task = Task.detached { () -> (IPReputation?, Date?) in
            let value = try? await IPWhoGeolocation.fetch(ip: ip, routingEnvironment: environment,
                                                         settingsEnvironment: settingsEnvironment)
            return (value, value == nil ? nil : Date())
        }
        inflight[cacheID] = task
        let result = await task.value
        inflight[cacheID] = nil
        if let value = result.0, let date = result.1 {
            retryAfter[cacheID] = nil
            entries[cacheID] = Entry(value: value, observedAt: date)
            if entries.count > 128, let oldest = entries.min(by: { $0.value.observedAt < $1.value.observedAt })?.key {
                entries.removeValue(forKey: oldest)
            }
        } else {
            retryAfter[cacheID] = Date().addingTimeInterval(60)
            if retryAfter.count > 128, let oldest = retryAfter.min(by: { $0.value < $1.value })?.key {
                retryAfter.removeValue(forKey: oldest)
            }
        }
        return result
    }
}
