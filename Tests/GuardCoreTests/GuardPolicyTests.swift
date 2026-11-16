import Foundation
import XCTest
@testable import GuardCore

final class GuardPolicyTests: XCTestCase {
    func testPolicyRoundTripAndInvalidFileFailClosed() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("policy.json").path
        XCTAssertEqual(try GuardPolicy.load(path: path), GuardPolicy())
        let policy = GuardPolicy(minimumScore: 84, runtimeMinimumScore: 88)
        try policy.save(path: path)
        XCTAssertEqual(try GuardPolicy.load(path: path), policy)
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertThrowsError(try GuardPolicy(minimumScore: 101).save(path: path))
        XCTAssertThrowsError(try GuardPolicy(enableUDPCheck: true, stunEndpoint: "https://bad").save(path: path))
        try Data(#"{"version":1,"minimumScore":84,"runtimeMinimumScore":88}"#.utf8).write(to: URL(fileURLWithPath: path))
        XCTAssertEqual(try GuardPolicy.load(path: path), policy)
        try Data("{}".utf8).write(to: URL(fileURLWithPath: path))
        XCTAssertThrowsError(try GuardPolicy.load(path: path))
    }

    func testOversizedPolicyIsRejectedBeforeDecoding() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("policy.json")
        try Data(repeating: 0x20, count: GuardPolicy.maximumFileSize + 1).write(to: path)
        XCTAssertThrowsError(try GuardPolicy.load(path: path.path))
    }
    func testPolicyDoesNotFollowSymlinks() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let link = root.appendingPathComponent("policy.json")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/etc/hosts")
        XCTAssertThrowsError(try GuardPolicy.load(path: link.path))
    }

    func testEncryptedDNSRequirementPersistsAndLegacyPolicyDefaultsToStrictAnyEncrypted() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("policy.json").path

        for required in DNSRequiredProtocol.allCases {
            let policy = GuardPolicy(dnsRequiredProtocol: required)
            try policy.save(path: path)
            XCTAssertEqual(try GuardPolicy.load(path: path), policy)
        }

        try Data(#"{"version":1,"minimumScore":80,"runtimeMinimumScore":80}"#.utf8)
            .write(to: URL(fileURLWithPath: path))
        XCTAssertEqual(try GuardPolicy.load(path: path).dnsRequiredProtocol, .anyEncrypted)
    }

    func testNotificationPreferencePersistsAndLegacyPolicyKeepsNotificationsOff() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("policy.json").path

        let enabled = GuardPolicy(notificationsEnabled: true)
        try enabled.save(path: path)
        XCTAssertTrue(try GuardPolicy.load(path: path).notificationsEnabled)

        try Data(#"{"version":1,"minimumScore":80,"runtimeMinimumScore":80}"#.utf8)
            .write(to: URL(fileURLWithPath: path))
        XCTAssertFalse(try GuardPolicy.load(path: path).notificationsEnabled)
    }

    func testProxyCheckConsentPersistsAndLegacyPolicyKeepsItOff() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("policy.json").path

        let enabled = GuardPolicy(allowProxyCheck: true)
        try enabled.save(path: path)
        XCTAssertTrue(try GuardPolicy.load(path: path).allowProxyCheck)

        try Data(#"{"version":1,"minimumScore":80,"runtimeMinimumScore":80}"#.utf8)
            .write(to: URL(fileURLWithPath: path))
        XCTAssertFalse(try GuardPolicy.load(path: path).allowProxyCheck)
    }

    func testTrustedEndpointPolicyCanonicalizesAndRejectsInvalidEntries() throws {
        let policy = GuardPolicy(trustedEndpoints: ["HTTPS://Gateway.Example:443/"])
        XCTAssertEqual(policy.trustedEndpoints, ["https://gateway.example"])
        XCTAssertTrue(policy.isValid)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("policy.json").path
        try policy.save(path: path)
        XCTAssertEqual(try GuardPolicy.load(path: path).trustedEndpoints, ["https://gateway.example"])
        let maximumEntries = (0..<32).map { index in
            let firstLabel = String(repeating: "a", count: 61) + String(format: "%02d", index)
            let host = [firstLabel, String(repeating: "b", count: 63),
                        String(repeating: "c", count: 63), String(repeating: "d", count: 61)]
                .joined(separator: ".")
            return "https://\(host)"
        }
        let boundaryPolicy = GuardPolicy(trustedEndpoints: maximumEntries)
        try boundaryPolicy.save(path: path)
        XCTAssertEqual(try GuardPolicy.load(path: path), boundaryPolicy)
        XCTAssertFalse(GuardPolicy(trustedEndpoints: ["http://gateway.example"]).isValid)
        XCTAssertFalse(GuardPolicy(trustedEndpoints: ["https://user:secret@gateway.example"]).isValid)
        XCTAssertFalse(GuardPolicy(trustedEndpoints: (0..<33).map { "https://gateway\($0).example" }).isValid)
    }

    func testRuntimeAssessmentGenerationTracksEveryScoringInput() {
        let baseline = GuardPolicy()
        XCTAssertTrue(baseline.hasSameRuntimeAssessment(as: GuardPolicy(notificationsEnabled: true)))
        XCTAssertTrue(baseline.hasSameRuntimeAssessment(as: GuardPolicy(minimumScore: 70)))
        XCTAssertFalse(baseline.hasSameRuntimeAssessment(as: GuardPolicy(runtimeMinimumScore: 70)))
        XCTAssertFalse(baseline.hasSameRuntimeAssessment(as: GuardPolicy(allowIPWho: true)))
        XCTAssertFalse(baseline.hasSameRuntimeAssessment(as: GuardPolicy(allowProxyCheck: true)))
        XCTAssertFalse(baseline.hasSameRuntimeAssessment(as: GuardPolicy(enableUDPCheck: true)))
        XCTAssertFalse(baseline.hasSameRuntimeAssessment(as: GuardPolicy(stunEndpoint: "stun.example:3479")))
        XCTAssertFalse(baseline.hasSameRuntimeAssessment(as:
            GuardPolicy(dnsRequiredProtocol: .dnsOverHTTPS)))
        XCTAssertFalse(baseline.hasSameRuntimeAssessment(as:
            GuardPolicy(trustedEndpoints: ["https://gateway.example"])))
    }
}
