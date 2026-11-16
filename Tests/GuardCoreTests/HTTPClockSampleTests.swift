import Foundation
import XCTest
@testable import GuardCore

final class HTTPClockSampleTests: XCTestCase {
    func testHTTPDateParsingAndClockUncertainty() throws {
        let header = "Fri, 13 Nov 2026 04:28:20 GMT"
        // Use a formatter-derived value to keep the test independent of the
        // host's locale and time zone.
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        let server = try XCTUnwrap(formatter.date(from: header))
        func sample(_ seconds: TimeInterval) throws -> HTTPClockSample {
            let end = server.addingTimeInterval(seconds)
            return try XCTUnwrap(HTTPClockSample.parse(header, start: end.addingTimeInterval(-0.2),
                                                      end: end, elapsed: 0.2))
        }
        let normal = try sample(5)
        XCTAssertEqual(normal.status(at: normal.observedAt), .passed)
        let boundary = try sample(30)
        XCTAssertEqual(boundary.status(at: boundary.observedAt),
                       .unknown(source: "https-clock-boundary", critical: true))
        let standard = try sample(35)
        XCTAssertEqual(standard.status(at: standard.observedAt), .triggered(.standard, deduplicationKey: nil))
        let elevated = try sample(-305)
        XCTAssertEqual(elevated.status(at: elevated.observedAt), .triggered(.elevated, deduplicationKey: nil))
        let elevatedBoundary = try sample(300)
        XCTAssertEqual(elevatedBoundary.status(at: elevatedBoundary.observedAt),
                       .unknown(source: "https-clock-boundary", critical: true))
        XCTAssertEqual(normal.status(at: normal.observedAt.addingTimeInterval(6)),
                       .unknown(source: "https-clock-stale", critical: true))
        XCTAssertNil(HTTPClockSample.parse(header, start: server, end: server.addingTimeInterval(8), elapsed: 0.2))
        XCTAssertNil(HTTPClockSample.parse("not a date", start: server, end: server, elapsed: 0))
    }
}
