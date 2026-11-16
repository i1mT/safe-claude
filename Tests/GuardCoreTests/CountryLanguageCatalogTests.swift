import XCTest
@testable import GuardCore

final class CountryLanguageCatalogTests: XCTestCase {
    func testCLDRSupportsMultilingualCountries() {
        let singapore = CountryLanguageCatalog.languages(for: "sg")
        XCTAssertEqual(singapore?.countryCode, "SG")
        XCTAssertTrue(singapore?.languages.contains("zh") == true)
        XCTAssertTrue(singapore?.languages.contains("en") == true)
        XCTAssertTrue(CountryLanguageCatalog.languages(for: "US")?.languages.contains("es") == true)
    }

    func testUnsupportedCountryDoesNotInventLanguages() {
        XCTAssertNil(CountryLanguageCatalog.languages(for: "ZZ"))
        XCTAssertNil(CountryLanguageCatalog.languages(for: "bad"))
    }
}
