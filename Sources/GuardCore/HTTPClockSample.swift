import Foundation

/// A time sample from a validated HTTPS response. The HTTP Date header has
/// whole-second resolution, and the server may produce it at any time during
/// the request; the uncertainty interval includes both effects.
public struct HTTPClockSample: Equatable, Sendable {
    let offset: TimeInterval
    let uncertainty: TimeInterval
    let observedAt: Date

    static func parse(_ value: String, start: Date, end: Date, elapsed: TimeInterval) -> Self? {
        guard value.utf8.count == 29, elapsed.isFinite, (0...3).contains(elapsed),
              abs(end.timeIntervalSince(start) - elapsed) < 0.5 else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        formatter.isLenient = false
        guard let server = formatter.date(from: value), formatter.string(from: server) == value else { return nil }
        return Self(offset: end.timeIntervalSince(server), uncertainty: elapsed + 1, observedAt: end)
    }

    /// Unknown near a threshold: the response cannot pinpoint the server's
    /// generation time more precisely than the interval above.
    func status(at now: Date) -> ObservationStatus {
        guard (0...5).contains(now.timeIntervalSince(observedAt)) else {
            return .unknown(source: "https-clock-stale", critical: true)
        }
        let magnitude = abs(offset)
        if magnitude - uncertainty > 300 { return .triggered(.elevated, deduplicationKey: nil) }
        if magnitude + uncertainty > 300 {
            return .unknown(source: "https-clock-boundary", critical: true)
        }
        if magnitude - uncertainty > 30 { return .triggered(.standard, deduplicationKey: nil) }
        if magnitude + uncertainty <= 30 { return .passed }
        return .unknown(source: "https-clock-boundary", critical: true)
    }
}
