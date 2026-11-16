import CryptoKit
import Darwin
import Foundation

/// History stores keyed digests of context and address rather than raw values.
public actor HistoryTracker {
    struct Sample: Codable, Sendable {
        let time: Date
        let address: Data
        let country: String?
        let asn: Int?
        let geoJump: Bool?
    }
    struct Summary: Sendable {
        let firstRun: Bool
        let triggered: [RuleObservation]
        let observations: [RuleObservation]
    }
    private struct Entry: Codable { let context: Data; let samples: [Sample] }
    private struct FileData: Codable { let version: Int; let entries: [Entry] }
    private let key: SymmetricKey
    private let path: String?
    private var history: [Data: [Sample]] = [:]
    private struct GeoPoint { let latitude: Double; let longitude: Double; let time: Date }
    private var lastGeoPoint: [Data: GeoPoint] = [:]
    public init() { key = SymmetricKey(size: .bits256); path = nil }
    public func clear() throws {
        let previous = history
        history.removeAll()
        do { try persist() } catch { history = previous; throw error }
    }
    public init(persistentPath: String, keyData: Data) throws {
        guard keyData.count == 32 else { throw GuardIPCError.invalidMessage }
        key = SymmetricKey(data: keyData)
        path = persistentPath
        try GuardIPC.prepareDirectory(URL(fileURLWithPath: persistentPath).deletingLastPathComponent().path)
        let fd = open(persistentPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            guard errno == ENOENT else { throw GuardIPCError.system(errno) }
            return
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == getuid(),
              (info.st_mode & 0o077) == 0, (0...2_000_000).contains(info.st_size) else { throw GuardIPCError.invalidPath }
        let data = try BoundedFile.read(fd, maximum: 2_000_000)
        let decoded = try JSONDecoder().decode(FileData.self, from: data)
        guard decoded.version == 1, decoded.entries.count <= 128,
              decoded.entries.allSatisfy({ $0.context.count == 32 && $0.samples.count <= 512 &&
                  $0.samples.allSatisfy { $0.address.count == 32 } }) else { throw GuardIPCError.invalidMessage }
        for entry in decoded.entries {
            guard history[entry.context] == nil else { throw GuardIPCError.invalidMessage }
            history[entry.context] = entry.samples
        }
    }
    private func persist() throws {
        guard let path else { return }
        let entries = history.map { Entry(context: $0.key, samples: $0.value) }
        let data = try JSONEncoder().encode(FileData(version: 1, entries: entries))
        guard data.count <= 2_000_000 else { throw GuardIPCError.invalidMessage }
        let tmp = path + "." + UUID().uuidString + ".tmp"
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw GuardIPCError.system(errno) }
        defer { close(fd); unlink(tmp) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw GuardIPCError.system(errno) }
                offset += n
            }
        }
        guard fsync(fd) == 0, rename(tmp, path) == 0 else { throw GuardIPCError.system(errno) }
    }
    func observe(environment: [String: String], trace: TraceObservation, reputation: IPReputation?, at now: Date) -> Summary? {
        guard let bytes = IPAddress.bytes(trace.ip),
              let encoded = try? JSONSerialization.data(withJSONObject: environment, options: [.sortedKeys]) else { return nil }
        let context = Data(HMAC<SHA256>.authenticationCode(for: encoded, using: key))
        let existing = history[context, default: []]
        if let last = existing.last, last.time > now { return nil }
        // If persistence fails, restore every pruned or added entry as well.
        // Otherwise the next identical observation could skip the write and
        // report a usable history that never reached disk.
        let previousHistory = history
        for (storedContext, storedSamples) in history {
            let retained = storedSamples.filter { (0...86_400).contains(now.timeIntervalSince($0.time)) }
            if retained.isEmpty { history.removeValue(forKey: storedContext) }
            else { history[storedContext] = retained }
        }
        var samples = existing.filter { (0...86_400).contains(now.timeIntervalSince($0.time)) }
        let asn: Int? = reputation.flatMap {
            IPAddress.bytes($0.ip) == bytes && ($0.countryCode == nil || trace.countryCode == nil || $0.countryCode == trace.countryCode)
                ? $0.autonomousSystem : nil
        }
        let geoPoint: GeoPoint? = reputation.flatMap {
            guard IPAddress.bytes($0.ip) == bytes,
                  let traceCountry = trace.countryCode, traceCountry == $0.countryCode,
                  let latitude = $0.latitude, let longitude = $0.longitude else {
                return nil
            }
            return GeoPoint(latitude: latitude, longitude: longitude, time: now)
        }
        let previousGeoPoint = lastGeoPoint[context]
        let geoDistance = geoPoint.flatMap { current -> Double? in
            guard let previousGeoPoint,
                  (0...1_800).contains(now.timeIntervalSince(previousGeoPoint.time)) else { return nil }
            return Self.distanceKilometers(latitudeA: previousGeoPoint.latitude,
                longitudeA: previousGeoPoint.longitude, latitudeB: current.latitude,
                longitudeB: current.longitude)
        }
        if let geoPoint { lastGeoPoint[context] = geoPoint }
        let currentGeoJump = geoDistance.map { $0 > 1_000 }
        // IPv6 privacy addresses in one /64 count as the same network exit.
        let prefix = bytes.first == 6 ? Array(bytes.prefix(9)) : bytes
        let address = Data(HMAC<SHA256>.authenticationCode(for: prefix, using: key))
        let sample = Sample(time: now, address: address, country: trace.countryCode, asn: asn,
                            geoJump: currentGeoJump)
        // Retain changes immediately and a regular five-minute heartbeat.
        // Repeated identical launch checks do not crowd a 24-hour window out.
        let needsSample = samples.last.map {
            $0.address != sample.address || $0.country != sample.country || $0.asn != sample.asn ||
            now.timeIntervalSince($0.time) >= 300
        } ?? true
        let persistGeoJump = currentGeoJump == true
        if needsSample || persistGeoJump { samples.append(sample) }
        if samples.count > 512 { samples.removeFirst(samples.count - 512) }
        history[context] = samples
        if history.count > 128, let oldest = history.min(by: { ($0.value.last?.time ?? .distantPast) < ($1.value.last?.time ?? .distantPast) })?.key {
            history.removeValue(forKey: oldest)
        }
        while history.values.reduce(0, { $0 + $1.count }) > 5_000 {
            guard let oldest = history.filter({ $0.key != context })
                .min(by: { ($0.value.last?.time ?? .distantPast) < ($1.value.last?.time ?? .distantPast) })?.key else { break }
            history.removeValue(forKey: oldest)
        }
        if needsSample || persistGeoJump {
            do { try persist() }
            catch {
                history = previousHistory
                if let previousGeoPoint { lastGeoPoint[context] = previousGeoPoint }
                else { lastGeoPoint.removeValue(forKey: context) }
                return nil
            }
        }
        func transitions<T: Equatable>(_ selected: [Sample], _ field: (Sample) -> T?) -> [Int] {
            guard selected.count > 1 else { return [] }
            return (1..<selected.count).filter { index in
                guard let before = field(selected[index-1]), let after = field(selected[index]) else { return false }
                return before != after
            }
        }
        let countryChanges = transitions(samples, { $0.country })
        let asnChanges = transitions(samples, { $0.asn })
        let recent = samples.filter { now.timeIntervalSince($0.time) <= 3_600 }
        let ipChanges = transitions(recent, { $0.address })
        var triggered: [RuleObservation] = []
        func eventKey(_ sample: Sample) -> String { "event:history-\(sample.time.timeIntervalSince1970)" }
        if let baseline = samples.first?.country, let latest = samples.last?.country, baseline != latest,
           let sample = samples.last {
            triggered.append(RuleObservation(id: "C01",
                status: .triggered(.standard, deduplicationKey: eventKey(sample))))
        }
        if countryChanges.count >= 2, let index = countryChanges.last {
            triggered.append(RuleObservation(id: "C02", status: .triggered(.standard, deduplicationKey: eventKey(samples[index]))))
        }
        if asnChanges.count >= 3, let index = asnChanges.last {
            triggered.append(RuleObservation(id: "C03", status: .triggered(.standard, deduplicationKey: eventKey(samples[index]))))
        }
        if ipChanges.count >= 6, let index = ipChanges.last {
            triggered.append(RuleObservation(id: "C04", status: .triggered(.standard, deduplicationKey: eventKey(recent[index]))))
        }
        let recentGeoJump = samples.last(where: {
            (0...1_800).contains(now.timeIntervalSince($0.time)) && $0.geoJump == true
        })
        if let recentGeoJump {
            triggered.append(RuleObservation(id: "C05",
                status: .triggeredAndUnknown(.standard, deduplicationKey: eventKey(recentGeoJump),
                    source: "geolocation-accuracy-unreported", critical: true),
                observedAt: recentGeoJump.time))
        }
        let continuous = samples.count >= 2 &&
            zip(samples, samples.dropFirst()).allSatisfy { pair in
                (0...600).contains(pair.1.time.timeIntervalSince(pair.0.time))
            } &&
            (samples.last.map { now.timeIntervalSince($0.time) <= 600 } ?? false)
        let span = samples.first.map { now.timeIntervalSince($0.time) } ?? 0
        let firstRun = !continuous || span < 86_100
        var observations = triggered
        let triggeredIDs = Set(triggered.map(\.id))
        for id in ["C01", "C02", "C03", "C04"] where !triggeredIDs.contains(id) {
            let requiredSpan: TimeInterval = id == "C04" ? 3_300 : 86_100
            if !continuous || span < requiredSpan {
                observations.append(RuleObservation(id: id, status: .notApplicable))
            } else if id == "C01" && samples.contains(where: { $0.country == nil }) {
                observations.append(RuleObservation(id: id, status: .unknown(source: "history-country-baseline", critical: true)))
            } else if id == "C02" && samples.contains(where: { $0.country == nil }) {
                observations.append(RuleObservation(id: id, status: .unknown(source: "history-country", critical: true)))
            } else if id == "C03" && samples.contains(where: { $0.asn == nil }) {
                observations.append(RuleObservation(id: id, status: .unknown(source: "history-asn", critical: true)))
            } else {
                observations.append(RuleObservation(id: id, status: .passed))
            }
        }
        if !triggeredIDs.contains("C05") {
            observations.append(RuleObservation(id: "C05", status: .unknown(
                source: geoDistance == nil ? "history-geolocation-window" : "geolocation-accuracy-unreported",
                critical: true), observedAt: now))
        }
        return Summary(firstRun: firstRun, triggered: triggered, observations: observations)
    }

    private static func distanceKilometers(latitudeA: Double, longitudeA: Double,
                                           latitudeB: Double, longitudeB: Double) -> Double {
        let radians = Double.pi / 180
        let latA = latitudeA * radians, latB = latitudeB * radians
        let deltaLat = (latitudeB - latitudeA) * radians
        let deltaLon = (longitudeB - longitudeA) * radians
        let a = sin(deltaLat / 2) * sin(deltaLat / 2) +
            cos(latA) * cos(latB) * sin(deltaLon / 2) * sin(deltaLon / 2)
        return 6_371.0088 * 2 * atan2(sqrt(a), sqrt(max(0, 1 - a)))
    }
}
