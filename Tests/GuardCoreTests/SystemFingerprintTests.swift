import Foundation
import XCTest
@testable import GuardCore

final class SystemFingerprintTests: XCTestCase {
    func testCurrentSystemCanBeFingerprinted() throws {
        let fingerprint = SystemFingerprint()
        let first = try XCTUnwrap(fingerprint.capture())
        XCTAssertEqual(first.count, 32)
        XCTAssertEqual(try XCTUnwrap(fingerprint.captureRouteConfiguration()).count, 32)
    }
    func testResolverChangesAlterOnlyOpaqueRouteDigest() throws {
        let fingerprint = SystemFingerprint()
        let proxies: [String: Any] = ["HTTPEnable": true]
        let firstDNS: [String: Any] = [
            "State:/Network/Global/DNS": ["ServerAddresses": ["192.0.2.53"]]
        ]
        let secondDNS: [String: Any] = [
            "State:/Network/Global/DNS": ["ServerAddresses": ["198.51.100.53"]]
        ]
        let first = try XCTUnwrap(fingerprint.routeConfigurationDigest(proxies: proxies, dns: firstDNS))
        let repeated = try XCTUnwrap(fingerprint.routeConfigurationDigest(proxies: proxies, dns: firstDNS))
        let changed = try XCTUnwrap(fingerprint.routeConfigurationDigest(proxies: proxies, dns: secondDNS))
        XCTAssertEqual(first, repeated)
        XCTAssertNotEqual(first, changed)
        XCTAssertFalse(String(decoding: first, as: UTF8.self).contains("192.0.2.53"))
    }
    func testActiveResolverDigestSetCanonicalizesAddressesAndFailsClosed() throws {
        let configuration: [String: Any] = [
            "State:/Network/Global/DNS": [
                "ServerAddresses": ["192.0.2.53", "2001:0db8:0:0:0:0:0:1"]
            ],
            "State:/Network/Service/wifi/DNS": [
                "ServerAddresses": ["2001:db8::1"]
            ],
        ]
        let digests = try XCTUnwrap(SystemFingerprint.resolverDigests(in: configuration))
        let v4 = try XCTUnwrap(DNSPathEvidence.resolverIdentity(host: "192.0.2.53", port: 53))
        let v6 = try XCTUnwrap(DNSPathEvidence.resolverIdentity(host: "2001:db8::1", port: 53))
        XCTAssertEqual(digests, [DNSPathEvidence.digest(v4), DNSPathEvidence.digest(v6)])
        XCTAssertNil(SystemFingerprint.resolverDigests(in: [
            "State:/Network/Global/DNS": ["ServerAddresses": ["not a resolver"]]
        ]))
        XCTAssertNil(SystemFingerprint.resolverDigests(in: [:]))
    }
    func testResolverReadsTLSAuthenticationNameWithoutExposingItInIdentity() throws {
        let configuration: [String: Any] = [
            "State:/Network/Global/DNS": [
                "ServerAddresses": ["192.0.2.53"],
                "ServerPort": 853,
                "ServerName": "Resolver.Example."
            ]
        ]
        let endpoint = try XCTUnwrap(SystemFingerprint.resolvers(in: configuration)?.first)
        XCTAssertEqual(endpoint.host, "192.0.2.53")
        XCTAssertEqual(endpoint.port, 853)
        XCTAssertEqual(endpoint.tlsServerName, "resolver.example")
        XCTAssertEqual(endpoint.identity, "192.0.2.53|853")
        XCTAssertFalse(endpoint.identity.contains("resolver.example"))

        let ambiguous: [String: Any] = [
            "State:/Network/Global/DNS": [
                "ServerAddresses": ["192.0.2.53"], "ServerPort": 853,
                "ServerName": "one.example"
            ],
            "State:/Network/Service/wifi/DNS": [
                "ServerAddresses": ["192.0.2.53"], "ServerPort": 853,
                "ServerName": "two.example"
            ]
        ]
        XCTAssertNil(SystemFingerprint.resolvers(in: ambiguous))
    }
    func testRepeatedDNSChangesFeedTheRouteChangeCounter() async throws {
        let fingerprint = SystemFingerprint()
        let tracker = RouteChangeTracker()
        let proxies: [String: Any] = [:]
        func resolver(_ address: String) throws -> Data {
            try XCTUnwrap(fingerprint.routeConfigurationDigest(proxies: proxies, dns: [
                "State:/Network/Global/DNS": ["ServerAddresses": [address]]
            ]))
        }
        await tracker.observe(try resolver("192.0.2.53"), at: 10)
        await tracker.observe(try resolver("192.0.2.54"), at: 11)
        await tracker.observe(try resolver("192.0.2.55"), at: 12)
        await tracker.observe(try resolver("192.0.2.56"), at: 13)
        let changes = await tracker.count(at: 13)
        XCTAssertEqual(changes, 3)
    }
    func testStableAcrossDictionaryOrderAndChangesWhenValuesChange() throws {
        let fingerprint = SystemFingerprint()
        let first: [String: Any] = ["proxy": ["enabled": 1, "host": "example"], "locale": "en_US"]
        let reordered: [String: Any] = ["locale": "en_US", "proxy": ["host": "example", "enabled": 1]]
        let changed: [String: Any] = ["locale": "ja_JP", "proxy": ["host": "example", "enabled": 1]]
        XCTAssertEqual(try XCTUnwrap(fingerprint.digest(first)), fingerprint.digest(reordered))
        XCTAssertNotEqual(fingerprint.digest(first), fingerprint.digest(changed))
    }
    func testSettingsChangesAndUnsafeFiles() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("settings.json")
        let fingerprint = SystemFingerprint()
        let absent = try XCTUnwrap(fingerprint.captureSettings(paths: [file.path]))
        try Data("{}".utf8).write(to: file)
        let created = try XCTUnwrap(fingerprint.captureSettings(paths: [file.path]))
        XCTAssertNotEqual(absent, created)
        try Data("{\"env\":{}}".utf8).write(to: file, options: .atomic)
        XCTAssertNotEqual(created, fingerprint.captureSettings(paths: [file.path]))
        try FileManager.default.removeItem(at: file)
        XCTAssertEqual(absent, fingerprint.captureSettings(paths: [file.path]))
        try FileManager.default.createSymbolicLink(atPath: file.path, withDestinationPath: "/dev/null")
        XCTAssertNil(fingerprint.captureSettings(paths: [file.path]))
    }

    func testSettingsDirectoryFingerprintTracksAdditionsAndContentMetadata() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fingerprint = SystemFingerprint()
        let empty = try XCTUnwrap(fingerprint.captureSettings(paths: [directory.path]))
        let firstFile = directory.appendingPathComponent("one.json")
        try Data("{\"env\":{}}".utf8).write(to: firstFile)
        let one = try XCTUnwrap(fingerprint.captureSettings(paths: [directory.path]))
        XCTAssertNotEqual(empty, one)
        let secondFile = directory.appendingPathComponent("two.json")
        try Data("{\"env\":{\"TZ\":\"UTC\"}}".utf8).write(to: secondFile)
        let two = try XCTUnwrap(fingerprint.captureSettings(paths: [directory.path]))
        XCTAssertNotEqual(one, two)
        try FileManager.default.removeItem(at: firstFile)
        XCTAssertNotEqual(two, fingerprint.captureSettings(paths: [directory.path]))
    }

}
