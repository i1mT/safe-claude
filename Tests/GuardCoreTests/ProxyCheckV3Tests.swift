import Foundation
import XCTest
@testable import GuardCore

final class ProxyCheckV3Tests: XCTestCase {
    private func isoStamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    func testAnonymousRequestUsesHTTPSAndNeverAddsCredentialQuery() throws {
        let url = try ProxyCheckV3.request(ip: "192.0.2.1")
        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "proxycheck.io")
        XCTAssertEqual(url.path, "/v3/192.0.2.1")
        XCTAssertFalse(url.absoluteString.contains("key="))
        XCTAssertTrue(url.absoluteString.contains("days=30"))
    }

    func testStrictDetectionParsingAndIPBinding() throws {
        let fixture = Data(#"{"status":"ok","192.0.2.1":{"detections":{"proxy":true,"vpn":false,"tor":false,"hosting":true,"anonymous":false,"risk":42},"attack_history":{"login_attempt":1,"vulnerability_probing":57}}}"#.utf8)
        let result = try ProxyCheckV3.decode(fixture, expectedIP: "192.0.2.1")
        XCTAssertEqual(result.isProxy, true)
        XCTAssertEqual(result.isHosting, true)
        XCTAssertEqual(result.risk, 42)
        XCTAssertEqual(result.hasAttacks, true)
        XCTAssertThrowsError(try ProxyCheckV3.decode(fixture, expectedIP: "192.0.2.2"))
    }

    func testAttackHistoryRequiresCompleteStrictBoundedCounts() throws {
        for (history, expected) in [
            (#"{"login_attempt":0,"vulnerability_probing":0}"#, false),
            (#"{"login_attempt":1}"#, true),
            (#"{}"#, false),
        ] {
            let fixture = Data("{\"status\":\"ok\",\"192.0.2.1\":{\"detections\":{},\"attack_history\":".utf8)
                + Data(history.utf8) + Data(#"}}"#.utf8)
            XCTAssertEqual(try ProxyCheckV3.decode(fixture, expectedIP: "192.0.2.1").hasAttacks, expected)
        }
        for history in ["null", "[]", #"{"login_attempt":true}"#,
                        #"{"bad key":1}"#, #"{"login_attempt":1000001}"#] {
            let fixture = Data("{\"status\":\"ok\",\"192.0.2.1\":{\"detections\":{},\"attack_history\":".utf8)
                + Data(history.utf8) + Data(#"}}"#.utf8)
            XCTAssertNil(try ProxyCheckV3.decode(fixture, expectedIP: "192.0.2.1").hasAttacks)
        }
    }

    func testUnknownAndMalformedSignalsDoNotBecomeClean() throws {
        let fixture = Data(#"{"status":"ok","192.0.2.1":{"detections":{"proxy":0,"vpn":"false","risk":101}}}"#.utf8)
        let result = try ProxyCheckV3.decode(fixture, expectedIP: "192.0.2.1")
        XCTAssertNil(result.isProxy)
        XCTAssertNil(result.isVPN)
        XCTAssertNil(result.risk)
        XCTAssertThrowsError(try ProxyCheckV3.decode(Data(#"{"status":"denied"}"#.utf8), expectedIP: "192.0.2.1"))
    }

    func testDeviceEstimatesAreStrictlyParsedAndRemainUnknownWhenMissing() throws {
        func decode(_ estimate: String) throws -> ProxyCheckObservation {
            let fixture = Data("{\"status\":\"ok\",\"192.0.2.1\":{\"detections\":{},\"device_estimate\":\(estimate)}}".utf8)
            return try ProxyCheckV3.decode(fixture, expectedIP: "192.0.2.1")
        }
        let complete = try decode(#"{"address":25,"subnet":512}"#)
        XCTAssertEqual(complete.estimatedDevicesAtAddress, 25)
        XCTAssertEqual(complete.estimatedDevicesInSubnet, 512)

        let nulls = try decode(#"{"address":null,"subnet":null}"#)
        XCTAssertNil(nulls.estimatedDevicesAtAddress)
        XCTAssertNil(nulls.estimatedDevicesInSubnet)

        for malformed in [
            #"{"address":true,"subnet":512}"#,
            #"{"address":25.5,"subnet":512}"#,
            #"{"address":-1,"subnet":512}"#,
            #"{"address":1000000001,"subnet":512}"#,
            "null",
        ] {
            let result = try decode(malformed)
            XCTAssertNil(result.estimatedDevicesAtAddress, malformed)
            if malformed == "null" { XCTAssertNil(result.estimatedDevicesInSubnet) }
        }
    }

    func testProviderSourceTimestampRequiresStrictISO8601() throws {
        func decode(_ stamp: String) throws -> Date? {
            let fixture = Data("{\"status\":\"ok\",\"192.0.2.1\":{\"last_updated\":\"\(stamp)\",\"detections\":{}}}".utf8)
            return try ProxyCheckV3.decode(fixture, expectedIP: "192.0.2.1").sourceDataUpdatedAt
        }
        XCTAssertNotNil(try decode("2026-11-14T12:30:00Z"))
        XCTAssertNotNil(try decode("2026-11-14T12:30:00.123Z"))
        XCTAssertNil(try decode("yesterday"))
        XCTAssertNil(try decode("2026-11-14"))
    }

    func testResidentialProxyOperatorServiceIsScoredAndMissingMetadataStaysUnknown() throws {
        let now = Date()
        let local = LocalEnvironmentSnapshot.collect(environment: [:],
            systemTimeZone: TimeZone(identifier: "UTC")!, systemLocale: Locale(identifier: "en_US"),
            preferredLanguages: ["en"], targetHost: "api.anthropic.com", collectedAt: now)
        let trace = TraceProbeResult.observed(TraceObservation(
            targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let positive = Data("{\"status\":\"ok\",\"192.0.2.1\":{\"last_updated\":\"\(isoStamp(now))\",\"detections\":{},\"operator\":{\"services\":[\"residential_proxies\"]}}}".utf8)
        let positiveCheck = try ProxyCheckV3.decode(positive, expectedIP: "192.0.2.1")
        XCTAssertEqual(positiveCheck.operatorOffersResidentialProxies, true)
        let positiveRules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
            reputation: nil, countryLanguages: nil, firstRun: false, proxyCheck: positiveCheck,
            proxyCheckObservedAt: now, traceObservedAt: now, at: now)
        let positiveReport = SafetyEvaluator.evaluate(positiveRules)
        XCTAssertEqual(positiveReport.deductions.first { $0.ruleID == "B07" }?.points, 10)
        XCTAssertTrue(positiveReport.unknownRuleIDs.contains("B07"))
        XCTAssertEqual(positiveReport.ruleStatuses.first { $0.rule == "B07" }?.status, "triggeredUnknown")
        XCTAssertEqual(positiveReport.ruleStatuses.first { $0.rule == "B07" }?.source,
                       "proxycheck-p2p-unobserved")
        XCTAssertEqual(positiveReport.ruleStatuses.first { $0.rule == "B07" }?.observedAt, now)

        let knownClear = Data("{\"status\":\"ok\",\"192.0.2.1\":{\"last_updated\":\"\(isoStamp(now))\",\"detections\":{},\"operator\":{\"services\":[]}}}".utf8)
        let clearCheck = try ProxyCheckV3.decode(knownClear, expectedIP: "192.0.2.1")
        XCTAssertEqual(clearCheck.operatorOffersResidentialProxies, false)
        let clearRules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
            reputation: nil, countryLanguages: nil, firstRun: false, proxyCheck: clearCheck,
            proxyCheckObservedAt: now, traceObservedAt: now, at: now)
        XCTAssertEqual(clearRules.first { $0.id == "B07" }?.status,
                       .unknown(source: "proxycheck-p2p-unobserved", critical: false))

        let missing = Data(#"{"status":"ok","192.0.2.1":{"detections":{}}}"#.utf8)
        let missingCheck = try ProxyCheckV3.decode(missing, expectedIP: "192.0.2.1")
        XCTAssertNil(missingCheck.operatorOffersResidentialProxies)
        let missingRules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
            reputation: nil, countryLanguages: nil, firstRun: false, proxyCheck: missingCheck,
            proxyCheckObservedAt: now, traceObservedAt: now, at: now)
        XCTAssertEqual(missingRules.first { $0.id == "B07" }?.status,
                       .unknown(source: "proxycheck-p2p-unobserved", critical: false))
    }

    func testHighAddressDeviceEstimateScoresButDoesNotClaimP2PWasVerified() throws {
        let now = Date()
        let local = LocalEnvironmentSnapshot.collect(environment: [:],
            systemTimeZone: TimeZone(identifier: "UTC")!, systemLocale: Locale(identifier: "en_US"),
            preferredLanguages: ["en"], targetHost: "api.anthropic.com", collectedAt: now)
        let trace = TraceProbeResult.observed(TraceObservation(
            targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))

        func assessment(_ count: Int?) throws -> SafetyEvaluation {
            let estimate = count.map(String.init) ?? "null"
            let body = Data("{\"status\":\"ok\",\"192.0.2.1\":{\"last_updated\":\"\(isoStamp(now))\",\"detections\":{},\"device_estimate\":{\"address\":\(estimate),\"subnet\":512},\"operator\":{\"services\":[]}}}".utf8)
            let proxy = try ProxyCheckV3.decode(body, expectedIP: "192.0.2.1")
            let observations = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
                reputation: nil, countryLanguages: nil, firstRun: false, proxyCheck: proxy,
                proxyCheckObservedAt: now, traceObservedAt: now, at: now)
            return SafetyEvaluator.evaluate(observations)
        }

        let high = try assessment(ProxyCheckV3.highAddressDeviceEstimateThreshold)
        XCTAssertEqual(high.deductions.first { $0.ruleID == "B07" }?.points, 10)
        XCTAssertTrue(high.unknownRuleIDs.contains("B07"))
        XCTAssertEqual(high.ruleStatuses.first { $0.rule == "B07" }?.status, "triggeredUnknown")

        let below = try assessment(ProxyCheckV3.highAddressDeviceEstimateThreshold - 1)
        XCTAssertNil(below.deductions.first { $0.ruleID == "B07" })
        XCTAssertTrue(below.unknownRuleIDs.contains("B07"))

        let unavailable = try assessment(nil)
        XCTAssertNil(unavailable.deductions.first { $0.ruleID == "B07" })
        XCTAssertTrue(unavailable.unknownRuleIDs.contains("B07"))

        let staleBody = Data("{\"status\":\"ok\",\"192.0.2.1\":{\"last_updated\":\"\(isoStamp(now.addingTimeInterval(-21_601)))\",\"detections\":{},\"device_estimate\":{\"address\":100},\"operator\":{\"services\":[\"residential_proxies\"]}}}".utf8)
        let stale = try ProxyCheckV3.decode(staleBody, expectedIP: "192.0.2.1")
        let staleRules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
            reputation: nil, countryLanguages: nil, firstRun: false, proxyCheck: stale,
            proxyCheckObservedAt: now, traceObservedAt: now, at: now)
        let staleReport = SafetyEvaluator.evaluate(staleRules)
        XCTAssertNil(staleReport.deductions.first { $0.ruleID == "B07" })
        XCTAssertTrue(staleReport.unknownRuleIDs.contains("B07"))
    }

    func testRequestIsPinnedToKnownSchemaAndOptOut() throws {
        let url = try ProxyCheckV3.request(ip: "2001:db8::1")
        XCTAssertEqual(url.host, "proxycheck.io")
        XCTAssertEqual(url.path, "/v3/2001:db8::1")
        XCTAssertEqual(url.query, "tag=0&risk=2&days=30&ver=24-June-2026")
        XCTAssertThrowsError(try ProxyCheckV3.request(ip: "attacker.example"))
        XCTAssertEqual(try ProxyCheckV3.request(ip: "192.0.2.1", apiKey: "123-ABC").query,
                       "tag=0&risk=2&days=30&ver=24-June-2026&key=123-ABC")
        for invalid in ["", "abc&tag=1", "abc\nurl=evil", String(repeating: "x", count: 129)] {
            XCTAssertThrowsError(try ProxyCheckV3.request(ip: "192.0.2.1", apiKey: invalid))
        }
    }

    func testKeyAndAddressAreOnlySentThroughStandardInput() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("curl")
        let script = """
        #!/bin/sh
        case "$*" in *fixture-secret*|*192.0.2.1*) exit 21;; esac
        IFS= read -r config
        case "$config" in *fixture-secret*192.0.2.1*) exit 22;; esac
        case "$config" in *192.0.2.1*fixture-secret*) ;; *) exit 23;; esac
        printf '{"status":"ok","192.0.2.1":{"detections":{}}}\\n__SAFE_STATUS__=200\\n'
        """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let url = try ProxyCheckV3.request(ip: "192.0.2.1", apiKey: "fixture-secret")
        let data = try GeolocationTransport.get(url: url, environment: [:], executable: executable,
                                                systemProxy: .inactive)
        XCTAssertEqual(try ProxyCheckV3.decode(data, expectedIP: "192.0.2.1").ip, "192.0.2.1")
        let injected = URL(string: "https://proxycheck.io/v3/192.0.2.1?tag=0&ver=24-June-2026&key=x&tag=1")!
        XCTAssertThrowsError(try GeolocationTransport.get(url: injected, environment: [:],
                                                          executable: executable, systemProxy: .inactive))
    }

    func testRiskDoesNotDoubleCountCoveredSignals() throws {
        let local = LocalEnvironmentSnapshot.collect(environment: [:], systemTimeZone: TimeZone(identifier: "Asia/Shanghai")!,
            systemLocale: Locale(identifier: "zh_CN"), preferredLanguages: ["zh-CN"],
            targetHost: "api.anthropic.com", collectedAt: Date())
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let fixture = Data(#"{"status":"ok","192.0.2.1":{"detections":{"proxy":true,"vpn":true,"tor":false,"hosting":true,"anonymous":false,"risk":100}}}"#.utf8)
        let check = try ProxyCheckV3.decode(fixture, expectedIP: "192.0.2.1")
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace, reputation: nil, countryLanguages: nil,
            firstRun: false, proxyCheck: check, proxyCheckObservedAt: local.collectedAt,
            traceObservedAt: local.collectedAt, at: local.collectedAt)
        let result = SafetyEvaluator.evaluate(rules)
        XCTAssertTrue(result.deductions.contains { $0.ruleID == "B08" && $0.points == 20 })
        XCTAssertFalse(result.deductions.contains { ["B04", "B05"].contains($0.ruleID) })
    }

    func testSecondProviderCannotEraseFirstProviderRisk() throws {
        let now = Date()
        let local = LocalEnvironmentSnapshot.collect(environment: [:], systemTimeZone: TimeZone(identifier: "UTC")!,
            systemLocale: Locale(identifier: "en_US"), preferredLanguages: ["en-US"],
            targetHost: "api.anthropic.com", collectedAt: now)
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let reputation = IPReputation(ip: "192.0.2.1", countryCode: "US", timeZone: "UTC",
            autonomousSystem: 123, isDatacenter: true, isVPN: nil, isProxy: nil, isTor: true, isAbuser: nil)
        for fields in [#""tor":false,"hosting":false"#, #""tor":null,"hosting":null"#] {
            let fixture = Data(#"{"status":"ok","192.0.2.1":{"detections":{"#.utf8) +
                Data(fields.utf8) + Data(#"}}}"#.utf8)
            let check = try ProxyCheckV3.decode(fixture, expectedIP: "192.0.2.1")
            let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace, reputation: reputation,
                countryLanguages: nil, firstRun: false, proxyCheck: check, proxyCheckObservedAt: now,
                traceObservedAt: now, reputationObservedAt: now, at: now)
            XCTAssertEqual(rules.first { $0.id == "B01" }?.status, .triggered(.standard, deduplicationKey: nil))
            XCTAssertEqual(rules.first { $0.id == "B05" }?.status, .triggered(.standard, deduplicationKey: nil))
            if fields.contains("false") {
                XCTAssertEqual(rules.first { $0.id == "H03" }?.status, .triggered(.standard, deduplicationKey: nil))
            }
        }
    }
}
