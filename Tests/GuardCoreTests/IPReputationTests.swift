import Foundation
import XCTest
@testable import GuardCore

final class IPReputationTests: XCTestCase {
    func testKeyIsInPostBodyAndNeverURL() throws {
        let request = try IPAPIAdapter.makeRequest(ip: "192.0.2.1", apiKey: "fixture-secret")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url?.absoluteString, "https://api.ipapi.is/")
        XCTAssertFalse(try XCTUnwrap(request.url).absoluteString.contains("fixture-secret"))
        let body = try XCTUnwrap(request.httpBody)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["key"] as? String, "fixture-secret")
        XCTAssertEqual(json["ips"] as? [String], ["192.0.2.1"])
    }

    func testIPAPIKeyRejectsControlCharactersAndOversizedValues() {
        XCTAssertThrowsError(try IPAPIAdapter.makeRequest(ip: "192.0.2.1", apiKey: "bad\nkey"))
        XCTAssertThrowsError(try IPAPIAdapter.makeRequest(ip: "192.0.2.1",
                                                          apiKey: String(repeating: "k", count: 257)))
    }

    func testRejectsHostnamesAndEmptyKeys() {
        XCTAssertThrowsError(try IPAPIAdapter.makeRequest(ip: "example.com", apiKey: "key"))
        XCTAssertThrowsError(try IPAPIAdapter.makeRequest(ip: "192.0.2.1", apiKey: ""))
    }

    func testParsesKeyedResponseWithoutTreatingMissingFlagsAsFalse() throws {
        let json = """
        {"192.0.2.1":{"ip":"192.0.2.1","is_tor":true,"is_vpn":false,
          "is_proxy":null,"is_abuser":1,"asn":{"asn":64500},
          "location":{"country_code":"us","timezone":"America/New_York"}}}
        """
        let result = try IPAPIAdapter.decode(Data(json.utf8), expectedIP: "192.0.2.1")
        XCTAssertEqual(result.countryCode, "US")
        XCTAssertEqual(result.timeZone, "America/New_York")
        XCTAssertEqual(result.autonomousSystem, 64500)
        XCTAssertEqual(result.isTor, true)
        XCTAssertEqual(result.isVPN, false)
        XCTAssertNil(result.isProxy)
        XCTAssertNil(result.isAbuser)
        XCTAssertNil(result.isDatacenter)
    }

    func testRejectsWrongIPAndInvalidResponse() {
        let wrong = Data(#"{"ip":"192.0.2.2"}"#.utf8)
        XCTAssertThrowsError(try IPAPIAdapter.decode(wrong, expectedIP: "192.0.2.1")) {
            XCTAssertEqual($0 as? ReputationError, .mismatchedAddress)
        }
        XCTAssertThrowsError(try IPAPIAdapter.decode(Data("{}".utf8), expectedIP: "192.0.2.1"))
    }

    func testEquivalentIPv6AndInvalidMetadata() throws {
        let data = Data(#"{"ip":"2001:db8::1","location":{"country_code":"??","timezone":"invalid/zone"},"asn":{"asn":true}}"#.utf8)
        let result = try IPAPIAdapter.decode(data, expectedIP: "2001:0db8:0:0:0:0:0:1")
        XCTAssertNil(result.countryCode)
        XCTAssertNil(result.timeZone)
        XCTAssertNil(result.autonomousSystem)
    }

    func testProviderVPNTruthyValuesAreNotTreatedAsClean() throws {
        for field in [#""known-provider""#, "1", #"{"provider":"example"}"#] {
            let data = Data("{\"ip\":\"192.0.2.1\",\"is_vpn\":\(field)}".utf8)
            let result = try IPAPIAdapter.decode(data, expectedIP: "192.0.2.1")
            XCTAssertEqual(result.isVPN, true)
        }
        let unknown = Data(#"{"ip":"192.0.2.1","is_vpn":null}"#.utf8)
        XCTAssertNil(try IPAPIAdapter.decode(unknown, expectedIP: "192.0.2.1").isVPN)
    }

    func testProviderAbuseAndProxySignalsRequireStrictBooleans() throws {
        let positive = Data(#"{"ip":"192.0.2.1","is_abuser":true,"is_proxy":true}"#.utf8)
        let value = try IPAPIAdapter.decode(positive, expectedIP: "192.0.2.1")
        XCTAssertEqual(value.isAbuser, true)
        XCTAssertEqual(value.isProxy, true)
        let malformed = Data(#"{"ip":"192.0.2.1","is_abuser":1,"is_proxy":"false"}"#.utf8)
        let invalid = try IPAPIAdapter.decode(malformed, expectedIP: "192.0.2.1")
        XCTAssertNil(invalid.isAbuser)
        XCTAssertNil(invalid.isProxy)
    }

    func testPOSTKeepsProviderKeyAndAddressOutOfCurlArguments() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("fake-curl")
        let script = """
        #!/bin/sh
        case "$*" in *fixture-secret*|*192.0.2.1*|*api.ipapi.is*) exit 21;; esac
        [ "$https_proxy" = "http://proxy-user:proxy-secret@127.0.0.1:8123" ] || exit 22
        [ -z "${HTTPS_PROXY+x}" ] || exit 23
        case "$*" in *"--data-binary @-"*) ;; *) exit 24;; esac
        body=$(cat)
        case "$body" in *fixture-secret*) ;; *) exit 25;; esac
        case "$body" in *192.0.2.1*) ;; *) exit 26;; esac
        printf '{"192.0.2.1":{"ip":"192.0.2.1","is_abuser":true,"is_proxy":true}}\\n__SAFE_STATUS__=200\\n'
        """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let request = try IPAPIAdapter.makeRequest(ip: "192.0.2.1", apiKey: "fixture-secret")
        let body = try XCTUnwrap(request.httpBody)
        let response = try GeolocationTransport.post(url: XCTUnwrap(request.url), body: body,
            environment: ["HTTPS_PROXY": "http://proxy-user:proxy-secret@127.0.0.1:8123"],
            executable: executable, systemProxy: .inactive)
        let value = try IPAPIAdapter.decode(response, expectedIP: "192.0.2.1")
        XCTAssertEqual(value.isAbuser, true)
        XCTAssertEqual(value.isProxy, true)
    }
}
