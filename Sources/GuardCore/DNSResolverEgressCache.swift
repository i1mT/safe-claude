import CryptoKit
import Foundation

public struct DNSResolverCountrySample: Sendable, Equatable {
    public let resolverDigest: String
    public let countryCode: String?
    public let observedAt: Date

    public init(resolverDigest: String, countryCode: String?, observedAt: Date) {
        self.resolverDigest = resolverDigest
        self.countryCode = countryCode
        self.observedAt = observedAt
    }
}

/// Short-lived, network-generation-bound cache for resolver egress discovery.
/// Egress IPs stay in memory and are never persisted or included in IPC.
public actor DNSResolverEgressCache {
    public static let shared = DNSResolverEgressCache()
    public static let maximumResolvers = 8
    public static let lifetime: TimeInterval = 900

    private struct Entry {
        let address: String
        let observedAt: Date
    }
    private struct LookupResult: Sendable {
        let address: String?
        let observedAt: Date?
    }

    private let key = SymmetricKey(size: .bits256)
    private var entries: [Data: Entry] = [:]
    private var inFlight: [Data: Task<LookupResult, Never>] = [:]
    private var retryAfter: [Data: Date] = [:]

    public func observe(_ endpoints: [DNSResolverEndpoint], networkEpoch: Int,
                        networkFingerprint: Data, environment: [String: String],
                        settingsEnvironment: [String: String] = [:]) async -> [DNSResolverCountrySample] {
        guard !endpoints.isEmpty, endpoints.count <= Self.maximumResolvers,
              networkFingerprint.count == 32 else { return [] }
        return await withTaskGroup(of: DNSResolverCountrySample?.self) { group in
            for endpoint in endpoints {
                group.addTask {
                    let result = await self.lookup(endpoint, networkEpoch: networkEpoch,
                        networkFingerprint: networkFingerprint)
                    guard let address = result.address, let probeAt = result.observedAt else { return nil }
                    let (geo, geoAt) = await IPWhoCache.shared.observe(ip: address,
                        environment: environment, settingsEnvironment: settingsEnvironment)
                    guard let geo, let geoAt, let country = geo.countryCode else { return nil }
                    return DNSResolverCountrySample(resolverDigest: endpoint.digest,
                        countryCode: country, observedAt: min(probeAt, geoAt))
                }
            }
            var samples: [DNSResolverCountrySample] = []
            for await sample in group {
                if let sample { samples.append(sample) }
            }
            return samples.sorted { $0.resolverDigest < $1.resolverDigest }
        }
    }

    private func lookup(_ endpoint: DNSResolverEndpoint, networkEpoch: Int,
                        networkFingerprint: Data) async -> LookupResult {
        var context = Data()
        context.append(Data(endpoint.digest.utf8))
        context.append(contentsOf: withUnsafeBytes(of: Int64(networkEpoch).bigEndian, Array.init))
        context.append(networkFingerprint)
        let cacheID = Data(HMAC<SHA256>.authenticationCode(for: context, using: key))
        let now = Date()
        if let cached = entries[cacheID], (0...Self.lifetime).contains(now.timeIntervalSince(cached.observedAt)) {
            return LookupResult(address: cached.address, observedAt: cached.observedAt)
        }
        if retryAfter[cacheID].map({ $0 > now }) == true { return LookupResult(address: nil, observedAt: nil) }
        if let task = inFlight[cacheID] { return await task.value }

        let task = Task.detached(priority: .utility) {
            let address = DNSResolverEgressProbe.observe(endpoint)
            return LookupResult(address: address, observedAt: address == nil ? nil : Date())
        }
        inFlight[cacheID] = task
        let result = await task.value
        inFlight[cacheID] = nil
        if let address = result.address, let observedAt = result.observedAt {
            retryAfter[cacheID] = nil
            entries[cacheID] = Entry(address: address, observedAt: observedAt)
            if entries.count > 64, let oldest = entries.min(by: { $0.value.observedAt < $1.value.observedAt })?.key {
                entries.removeValue(forKey: oldest)
            }
        } else {
            retryAfter[cacheID] = Date().addingTimeInterval(60)
            if retryAfter.count > 64, let oldest = retryAfter.min(by: { $0.value < $1.value })?.key {
                retryAfter.removeValue(forKey: oldest)
            }
        }
        return result
    }
}
