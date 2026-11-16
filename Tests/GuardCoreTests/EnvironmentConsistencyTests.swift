import XCTest
@testable import GuardCore

final class EnvironmentConsistencyTests: XCTestCase {
    func testTimeZoneMismatchAndMissingData() throws {
        let shanghai = try XCTUnwrap(TimeZone(identifier: "Asia/Shanghai"))
        XCTAssertEqual(EnvironmentConsistency.timeZone(local: shanghai, expectedIdentifiers: ["America/New_York"]),
                       .different)
        // Identical current UTC offsets must not hide a region mismatch.
        XCTAssertEqual(EnvironmentConsistency.timeZone(local: shanghai, expectedIdentifiers: ["Asia/Singapore"]),
                       .different)
        XCTAssertEqual(EnvironmentConsistency.timeZone(local: shanghai, expectedIdentifiers: []), .unknown)
        XCTAssertEqual(EnvironmentConsistency.timeZone(local: shanghai, expectedIdentifiers: ["invalid/zone"]), .unknown)
    }

    func testTimeZoneAliasesAndDSTAreComparedAcrossSeasons() throws {
        let ny = try XCTUnwrap(TimeZone(identifier: "America/New_York"))
        let january = Date(timeIntervalSince1970: 1_767_225_600)
        XCTAssertEqual(EnvironmentConsistency.timeZone(local: ny, expectedIdentifiers: ["US/Eastern"], at: january),
                       .matching)
        // Lima may match New York's UTC offset in winter but does not observe
        // the same DST schedule.
        XCTAssertEqual(EnvironmentConsistency.timeZone(local: ny, expectedIdentifiers: ["America/Lima"], at: january),
                       .different)
    }

    func testMultipleExpectedZonesAndExplicitTZ() throws {
        let zone = try XCTUnwrap(TimeZone(identifier: "Asia/Shanghai"))
        XCTAssertEqual(EnvironmentConsistency.timeZone(local: zone,
            expectedIdentifiers: ["America/New_York", "Asia/Shanghai"]), .matching)
        XCTAssertEqual(EnvironmentConsistency.processTimeZone(environment: [:], system: zone), .matching)
        XCTAssertEqual(EnvironmentConsistency.processTimeZone(environment: ["TZ": "Not/AZone"], system: zone),
                       .unknown)
        XCTAssertEqual(EnvironmentConsistency.processTimeZone(environment: ["TZ": "America/New_York"], system: zone),
                       .different)
    }

    func testCountryLanguageSetsAndLocaleFormats() {
        XCTAssertEqual(EnvironmentConsistency.language(local: "zh_CN.UTF-8", expectedLanguages: ["en", "zh"]),
                       .matching)
        XCTAssertEqual(EnvironmentConsistency.language(local: "zh-Hans", expectedLanguages: ["en", "fr"]),
                       .different)
        XCTAssertEqual(EnvironmentConsistency.language(local: nil, expectedLanguages: ["en"]), .unknown)
    }

    func testProcessLocalePrecedenceAndCLocale() {
        XCTAssertEqual(EnvironmentConsistency.processLanguage(
            environment: ["LC_ALL": "fr_FR.UTF-8", "LANG": "en_US.UTF-8"],
            preferredLanguages: ["en-US"]), .different)
        XCTAssertEqual(EnvironmentConsistency.processLanguage(
            environment: ["LANG": "C.UTF-8"], preferredLanguages: ["zh-Hans-CN"]), .notApplicable)
        XCTAssertEqual(EnvironmentConsistency.processLanguage(
            environment: [:], preferredLanguages: ["zh-Hans-CN"]), .unknown)
    }
}
