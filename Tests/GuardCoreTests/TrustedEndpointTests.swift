import XCTest
@testable import GuardCore

final class TrustedEndpointTests: XCTestCase {
    func testCanonicalizesHTTPSOrigin() {
        XCTAssertEqual(TrustedEndpoint.canonicalOrigin("HTTPS://Gateway.Example:443/"),
                       "https://gateway.example")
        XCTAssertEqual(TrustedEndpoint.canonicalOrigin("https://gateway.example:8443"),
                       "https://gateway.example:8443")
    }

    func testRejectsCredentialAndNonOriginURLs() {
        for value in ["http://gateway.example", "https://user:pass@gateway.example",
                      "https://gateway.example/path", "https://gateway.example/?token=x",
                      "https://gateway.example/#fragment", "https://gateway.example:0"] {
            XCTAssertNil(TrustedEndpoint.canonicalOrigin(value), value)
        }
    }

    func testRejectsInvalidDNSLabels() {
        for value in ["https://-bad.example", "https://bad-.example",
                      "https://bad..example", "https://bad_.example",
                      "https://\(String(repeating: "a", count: 64)).example"] {
            XCTAssertNil(TrustedEndpoint.canonicalOrigin(value), value)
        }
    }

    func testTrustUsesExactOriginAndIncludesOfficialAPI() {
        XCTAssertTrue(TrustedEndpoint.isTrusted("https://api.anthropic.com", allowlist: []))
        XCTAssertTrue(TrustedEndpoint.isTrusted("https://GW.Example:443/", allowlist: ["https://gw.example"]))
        XCTAssertFalse(TrustedEndpoint.isTrusted("https://sub.gw.example", allowlist: ["https://gw.example"]))
        XCTAssertFalse(TrustedEndpoint.isTrusted("https://gw.example:8443", allowlist: ["https://gw.example"]))
    }
}
