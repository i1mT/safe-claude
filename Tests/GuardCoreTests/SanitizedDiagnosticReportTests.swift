import Foundation
import XCTest
@testable import GuardCore

final class SanitizedDiagnosticReportTests: XCTestCase {
    func testOnDiskExportIsPrivateAtomicAndExcludesSensitiveValues() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }

        let destination = root.appendingPathComponent("diagnostic.json")
        let victim = root.appendingPathComponent("victim.txt")
        let victimBytes = Data("must-remain-private".utf8)
        try victimBytes.write(to: victim)
        try FileManager.default.createSymbolicLink(at: destination, withDestinationURL: victim)
        let secrets = [
            "token-SECRET", "203.0.113.42", "2001:db8:85a3::8a2e:370:7334",
            "/Users/private/Project", "chat-body-SECRET", "proxy-password-SECRET",
        ]
        let response = GuardResponse(
            decision: "deny", safetyScore: 72, scoreUpperBound: 72,
            unknownCount: 1, reason: secrets.joined(separator: " "),
            ruleStatuses: [RuleReportStatus(rule: "A01", status: "triggered",
                                             source: secrets[0], remediation: secrets[3])]
        )
        let report = SanitizedDiagnosticReport(response: response,
                                               appVersion: "1.2.3",
                                               operatingSystem: "15.6.0")

        try SanitizedDiagnosticExport.write(report, to: destination)

        let attributes = try FileManager.default.attributesOfItem(atPath: destination.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(try Data(contentsOf: victim), victimBytes)
        XCTAssertEqual(attributes[.type] as? FileAttributeType, .typeRegular)
        let json = try String(contentsOf: destination, encoding: .utf8)
        for secret in secrets {
            XCTAssertFalse(json.contains(secret))
        }
        for forbiddenField in ["reason", "source", "remediation", "ticket", "sessions"] {
            XCTAssertFalse(json.contains("\"\(forbiddenField)\""))
        }
        XCTAssertTrue(json.contains("\"schemaVersion\""))
    }

    func testExportKeepsOnlyAllowlistedFieldsAndRules() throws {
        let secretValues = [
            "token-SECRET", "203.0.113.42", "/Users/private/Project",
            "chat-body-SECRET", "proxy-password-SECRET",
        ]
        let response = GuardResponse(
            decision: "deny",
            scoreUpperBound: 82,
            unknownCount: 2,
            unknownRules: ["A02", "../../private"],
            reason: secretValues.joined(separator: " "),
            findings: [
                GuardFinding(rule: "A01", points: 8),
                GuardFinding(rule: "../../private", points: 1000),
            ],
            ruleStatuses: [
                RuleReportStatus(rule: "A01", status: "triggered", points: 8,
                                 source: secretValues[0], observedAt: Date(),
                                 remediation: secretValues[1]),
                RuleReportStatus(rule: "A02", status: "unknown", source: secretValues[2]),
                RuleReportStatus(rule: "A03", status: secretValues[3]),
                RuleReportStatus(rule: "../../private", status: "passed"),
                RuleReportStatus(rule: "A02", status: "passed"),
            ],
            assessmentContext: .claudeLaunch,
            ticket: secretValues[4],
            sessions: [
                GuardSessionSummary(pid: 1234, startSeconds: 1, startMicroseconds: 2,
                                    isTopLevel: true, decision: "deny",
                                    safetyScore: 82, checkedAt: Date()),
            ]
        )
        let report = SanitizedDiagnosticReport(
            response: response, appVersion: "1.2.3", operatingSystem: "15.6.0"
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let json = String(decoding: try encoder.encode(report), as: UTF8.self)

        XCTAssertEqual(report.decision, "deny")
        XCTAssertEqual(report.findings.map(\.id), ["A01"])
        XCTAssertEqual(report.rules.map(\.id), ["A01", "A02"])
        XCTAssertEqual(report.unknownCount, 2)
        for secret in secretValues {
            XCTAssertFalse(json.contains(secret))
        }
        for forbiddenField in ["reason", "ticket", "sessions", "source", "remediation", "unknownRules"] {
            XCTAssertFalse(json.contains("\"\(forbiddenField)\""))
        }
    }

    func testInvalidScoresAndDecisionAreSanitized() {
        let response = GuardResponse(
            decision: "unexpected-private-value", safetyScore: 900,
            scoreUpperBound: -1, reason: "omitted"
        )
        let report = SanitizedDiagnosticReport(response: response, appVersion: "dev",
                                               operatingSystem: "15.6")
        XCTAssertEqual(report.decision, "hold")
        XCTAssertNil(report.safetyScore)
        XCTAssertNil(report.scoreUpperBound)
    }
}
