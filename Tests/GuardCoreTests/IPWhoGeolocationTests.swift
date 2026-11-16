import Foundation
import XCTest
@testable import GuardCore

final class IPWhoGeolocationTests: XCTestCase {
    func testFreeResponseContainsOnlyGeolocation() throws {
        let response = Data(#"{"success":true,"ip":"192.0.2.1","country_code":"us","latitude":40.7,"longitude":-74.0,"timezone":{"id":"America/New_York"},"connection":{"asn":64500},"security":{"vpn":false}}"#.utf8)
        let result = try IPWhoGeolocation.decode(response, expectedIP: "192.0.2.1")
        XCTAssertEqual(result.countryCode, "US")
        XCTAssertEqual(result.timeZone, "America/New_York")
        XCTAssertEqual(result.autonomousSystem, 64500)
        XCTAssertEqual(result.latitude, 40.7)
        XCTAssertEqual(result.longitude, -74.0)
        XCTAssertNil(result.isVPN)
        XCTAssertNil(result.isDatacenter)
    }

    func testInvalidCoordinatesRemainUnavailable() throws {
        let response = Data(#"{"success":true,"ip":"192.0.2.1","country_code":"us","latitude":91,"longitude":true}"#.utf8)
        let result = try IPWhoGeolocation.decode(response, expectedIP: "192.0.2.1")
        XCTAssertNil(result.latitude)
        XCTAssertNil(result.longitude)
    }

    func testMismatchedOrInvalidResponseCannotBecomeEvidence() {
        let response = Data(#"{"success":true,"ip":"192.0.2.2"}"#.utf8)
        XCTAssertThrowsError(try IPWhoGeolocation.decode(response, expectedIP: "192.0.2.1"))
        XCTAssertThrowsError(try IPWhoGeolocation.decode(Data(#"{"success":1,"ip":"192.0.2.1"}"#.utf8), expectedIP: "192.0.2.1"))
        XCTAssertThrowsError(try IPWhoGeolocation.request(ip: "example.com"))
    }

    func testIPv6RequestUsesHTTPS() throws {
        let request = try IPWhoGeolocation.request(ip: "2001:db8::1")
        XCTAssertEqual(request.url?.scheme, "https")
        XCTAssertEqual(request.url?.host, "ipwho.is")
        XCTAssertEqual(request.url?.lastPathComponent, "2001:db8::1")
    }
    func testUnsupportedProxyPreventsUnverifiedLookup() async {
        do {
            _ = try await IPWhoGeolocation.fetch(ip: "192.0.2.1", routingEnvironment: ["https_proxy": "socks5://127.0.0.1:1"])
            XCTFail("Lookup should not use URLSession with an unverified route")
        } catch let error as ReputationError {
            XCTAssertEqual(error, .routeUnverified)
        } catch {
            XCTFail("Unexpected error")
        }
    }
    func testVerifiedProxyIsPassedOnlyInChildEnvironment() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("fake-curl")
        let script = """
        #!/bin/sh
        [ "$1" = "-q" ] || exit 20
        [ "$https_proxy" = "http://fixture-user:fixture-secret@127.0.0.1:8123" ] || exit 21
        [ -z "${ANTHROPIC_API_KEY+x}" ] || exit 22
        case "$*" in *fixture-user*|*fixture-secret*|*192.0.2.1*) exit 23;; esac
        printf '{"success":true,"ip":"192.0.2.1"}\\n__SAFE_STATUS__=200\\n'
        """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let url = try XCTUnwrap(IPWhoGeolocation.request(ip: "192.0.2.1").url)
        let bytes = try GeolocationTransport.get(url: url, environment: [
            "HTTPS_PROXY": "http://fixture-user:fixture-secret@127.0.0.1:8123",
            "ANTHROPIC_API_KEY": "private"
        ], executable: executable)
        XCTAssertEqual(try IPWhoGeolocation.decode(bytes, expectedIP: "192.0.2.1").ip, "192.0.2.1")
    }
    func testClaudeSettingsProxyIsUsedForProviderLookup() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("fake-curl")
        let script = """
        #!/bin/sh
        [ "$https_proxy" = "http://settings-user:settings-secret@127.0.0.1:8123" ] || exit 21
        [ -z "${HTTPS_PROXY+x}" ] || exit 22
        case "$*" in *settings-secret*) exit 23;; esac
        printf '{"success":true,"ip":"192.0.2.1"}\\n__SAFE_STATUS__=200\\n'
        """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let url = try XCTUnwrap(IPWhoGeolocation.request(ip: "192.0.2.1").url)
        let bytes = try GeolocationTransport.get(url: url, environment: [:],
            settings: ["https_proxy": "http://settings-user:settings-secret@127.0.0.1:8123"],
            executable: executable, systemProxy: .inactive)
        XCTAssertEqual(try IPWhoGeolocation.decode(bytes, expectedIP: "192.0.2.1").ip, "192.0.2.1")
    }
    func testSystemProxyAndPACFailClosed() throws {
        for configuration: [String: Any] in [["HTTPSEnable": 1], ["ProxyAutoConfigEnable": 1],
                                              ["__SCOPED__": ["en0": ["SOCKSEnable": 1]]]] {
            XCTAssertEqual(SystemProxyState.evaluate(configuration), .configured)
            XCTAssertThrowsError(try GeolocationTransport.get(url: IPWhoGeolocation.request(ip: "192.0.2.1").url!,
                                                              environment: [:], systemProxy: .configured))
        }
        XCTAssertEqual(SystemProxyState.evaluate(["HTTPEnable": 0]), .inactive)
        XCTAssertEqual(SystemProxyState.evaluate(["HTTPEnable": "invalid"]), .unknown)
        XCTAssertEqual(SystemProxyState.evaluate(["__SCOPED__": ["en0": "unreadable"]]), .unknown)
    }
}
