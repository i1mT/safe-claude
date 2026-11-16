import CryptoKit
import Foundation
import XCTest
@testable import GuardCore

final class RouteBoundCacheIdentityTests: XCTestCase {
    func testDifferentSettingsRoutesCannotShareCachedEvidenceAndDigestHidesValues() throws {
        let key = SymmetricKey(data: Data(repeating: 7, count: 32))
        let firstRoute = ["https_proxy": "http://user:secret@127.0.0.1:8000"]
        let secondRoute = ["https_proxy": "http://user:secret@127.0.0.1:9000"]
        let first = try XCTUnwrap(RouteBoundCacheIdentity.make(ip: "192.0.2.1",
            environment: [:], settings: firstRoute, using: key))
        let second = try XCTUnwrap(RouteBoundCacheIdentity.make(ip: "192.0.2.1",
            environment: [:], settings: secondRoute, using: key))
        XCTAssertNotEqual(first, second)
        XCTAssertFalse(String(decoding: first, as: UTF8.self).contains("secret"))
        XCTAssertFalse(String(decoding: second, as: UTF8.self).contains("127.0.0.1"))
    }

    func testAnonymousAndKeyedProviderResultsNeverShareCacheIdentity() throws {
        let key = SymmetricKey(data: Data(repeating: 9, count: 32))
        let anonymous = try XCTUnwrap(RouteBoundCacheIdentity.make(ip: "192.0.2.1",
            environment: [:], settings: [:], using: key))
        let keyed = try XCTUnwrap(RouteBoundCacheIdentity.make(ip: "192.0.2.1",
            apiKey: "anonymous", environment: [:], settings: [:], using: key))
        XCTAssertNotEqual(anonymous, keyed)
    }
}
