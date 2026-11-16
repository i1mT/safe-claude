import Foundation
import XCTest
@testable import GuardCore

final class EnvironmentAssessmentTests: XCTestCase {
    private func snapshot() -> LocalEnvironmentSnapshot {
        LocalEnvironmentSnapshot.collect(environment: ["TZ": "America/New_York", "LANG": "en_US.UTF-8"],
            systemTimeZone: TimeZone(identifier: "Asia/Shanghai")!, systemLocale: Locale(identifier: "zh_CN"),
            preferredLanguages: ["zh-CN"], collectedAt: Date())
    }
    func testKnownFactsAccumulateWhileMissingAdaptersHold() {
        let reputation = IPReputation(ip: "192.0.2.1", countryCode: "US", timeZone: "America/New_York",
            autonomousSystem: 123, isDatacenter: true, isVPN: true, isProxy: false, isTor: false, isAbuser: false)
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: trace,
            reputation: reputation, countryLanguages: CountryLanguages(countryCode: "US", languages: ["en"]), firstRun: true, traceObservedAt: Date(), reputationObservedAt: Date())
        XCTAssertEqual(rules.count, 64)
        let evaluation = SafetyEvaluator.evaluate(rules)
        XCTAssertEqual(evaluation.decision, .hold)
        XCTAssertNil(evaluation.safetyScore)
        for id in ["B04", "B05", "E01", "E02", "E03", "E04", "E06", "H04"] {
            XCTAssertTrue(evaluation.deductions.contains { $0.ruleID == id }, id)
        }
    }
    func testNativeMacOSRuntimeMatchesSupportedE09Baseline() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false)
        #if os(macOS)
        XCTAssertEqual(rules.first { $0.id == "E09" }?.status, .passed)
        #else
        XCTAssertEqual(rules.first { $0.id == "E09" }?.status,
                       .triggered(.standard, deduplicationKey: nil))
        #endif
    }

    func testVirtualizedRuntimeTriggersE09AndUnavailableSignalStaysUnknown() {
        #if os(macOS)
        func evaluate(isVirtualized: Bool?) -> SafetyEvaluation {
            let local = LocalEnvironmentSnapshot.collect(environment: [:],
                systemTimeZone: TimeZone(identifier: "UTC"), systemLocale: Locale(identifier: "en_US"),
                preferredLanguages: ["en"], targetHost: "api.anthropic.com",
                collectedAt: Date(), isVirtualized: isVirtualized)
            let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil,
                reputation: nil, countryLanguages: nil, firstRun: false)
            return SafetyEvaluator.evaluate(rules)
        }
        let virtualized = evaluate(isVirtualized: true)
        XCTAssertEqual(virtualized.deductions.first { $0.ruleID == "E09" }?.points, 3)

        let sshSnapshot = LocalEnvironmentSnapshot.collect(
            environment: ["SSH_CONNECTION": "192.0.2.18 54821 198.51.100.4 22"],
            systemTimeZone: TimeZone(identifier: "UTC"), systemLocale: Locale(identifier: "en_US"),
            preferredLanguages: ["en"], targetHost: "api.anthropic.com",
            collectedAt: Date(), isVirtualized: false)
        let sshRules = EnvironmentAssessment.observations(snapshot: sshSnapshot, apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false)
        XCTAssertEqual(SafetyEvaluator.evaluate(sshRules).deductions.first { $0.ruleID == "E09" }?.points, 3)

        let unavailable = evaluate(isVirtualized: nil)
        XCTAssertFalse(unavailable.deductions.contains { $0.ruleID == "E09" })
        XCTAssertTrue(unavailable.unknownRuleIDs.contains("E09"))
        XCTAssertEqual(unavailable.ruleStatuses.first { $0.rule == "E09" }?.source,
                       "runtime-virtualization")
        #endif
    }

    func testE08ExplainsPrivilegedStatusReadAndRemainsCriticalUnknown() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false)
        XCTAssertEqual(rules.first { $0.id == "E08" }?.status,
            .unknown(source: "network-time-status-privileged", critical: true))
        let report = SafetyEvaluator.evaluate(rules)
        XCTAssertEqual(report.ruleStatuses.first { $0.rule == "E08" }?.source,
                       "network-time-status-privileged")
        XCTAssertEqual(report.decision, .hold)
    }
    func testClaudeFailureCountsPersistInEveryRuntimeReassessment() {
        let counts = ClaudeFailureCounts(apiFailuresInMinute: 11,
            authenticationFailuresInTenMinutes: 3)
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false,
            claudeFailureCounts: counts)
        XCTAssertEqual(rules.first { $0.id == "G03" }?.status,
            .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "G04" }?.status,
            .triggered(.standard, deduplicationKey: nil))

        let belowThresholds = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false,
            claudeFailureCounts: ClaudeFailureCounts(apiFailuresInMinute: 10,
                authenticationFailuresInTenMinutes: 2))
        XCTAssertEqual(belowThresholds.first { $0.id == "G03" }?.status, .passed)
        XCTAssertEqual(belowThresholds.first { $0.id == "G04" }?.status, .passed)
    }
    func testA02RequiresFreshSuccessfulTraceThroughConfiguredProxy() {
        let now = Date()
        let trace = TraceProbeResult.observed(TraceObservation(
            targetHost: ClaudeTraceTarget.api.rawValue, ip: "192.0.2.1", countryCode: "US"))
        func status(_ result: TraceProbeResult?, observedAt: Date?, configured: Bool?) -> ObservationStatus? {
            let local = LocalEnvironmentSnapshot.collect(environment: [:],
                systemTimeZone: TimeZone(identifier: "UTC"), systemLocale: Locale(identifier: "en_US"),
                preferredLanguages: ["en"], collectedAt: now)
            return EnvironmentAssessment.observations(snapshot: local, apiTrace: result,
                reputation: nil, countryLanguages: nil, firstRun: false,
                traceObservedAt: observedAt, effectiveProxyConfigured: configured,
                at: now).first { $0.id == "A02" }?.status
        }
        XCTAssertEqual(status(trace, observedAt: now, configured: true), .passed)
        XCTAssertEqual(status(trace, observedAt: now, configured: false), .notApplicable)
        XCTAssertEqual(status(trace, observedAt: now.addingTimeInterval(-6), configured: true),
            .unknown(source: "proxy-connectivity-unverified", critical: true))
        XCTAssertEqual(status(.unknown(reason: "TRACE_REQUEST_FAILED"), observedAt: now, configured: true),
            .unknown(source: "proxy-connectivity-unverified", critical: true))
        XCTAssertEqual(status(trace, observedAt: now, configured: nil),
            .unknown(source: "proxy-connectivity-unverified", critical: true))
    }
    func testHistoricalGeolocationJumpFlowsIntoC05Scoring() {
        let historical = RuleObservation(id: "C05",
            status: .triggered(.standard, deduplicationKey: "event:geo-jump"))
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false,
            historicalTriggers: [historical])
        let evaluation = SafetyEvaluator.evaluate(rules)
        XCTAssertTrue(evaluation.deductions.contains {
            $0.ruleID == "C05" && $0.points == SafetyRuleCatalog.weights["C05"]
        })
        XCTAssertEqual(evaluation.ruleStatuses.first { $0.rule == "C05" }?.status, "triggered")
    }
    func testRuleSampleTimesReflectCollectorObservationsAndLeaveGapsEmpty() {
        let sample = Date()
        let local = LocalEnvironmentSnapshot.collect(environment: [:],
            systemTimeZone: TimeZone(identifier: "UTC")!, systemLocale: Locale(identifier: "en_US"),
            preferredLanguages: ["en"], collectedAt: sample)
        let trace = TraceProbeResult.observed(TraceObservation(
            targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let reputation = IPReputation(ip: "192.0.2.1", countryCode: "US", timeZone: "UTC",
            autonomousSystem: 64500, isDatacenter: false, isVPN: false, isProxy: false,
            isTor: false, isAbuser: false)
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
            reputation: reputation, countryLanguages: nil, firstRun: false,
            traceObservedAt: sample,
            reputationObservedAt: sample.addingTimeInterval(-8))
        XCTAssertEqual(rules.first { $0.id == "D05" }?.observedAt, sample)
        XCTAssertNil(rules.first { $0.id == "B01" }?.observedAt)
        XCTAssertEqual(rules.first { $0.id == "E01" }?.observedAt, sample.addingTimeInterval(-8))
        XCTAssertNil(rules.first { $0.id == "D01" }?.observedAt)
        let report = SafetyEvaluator.evaluate(rules)
        XCTAssertNil(report.ruleStatuses.first { $0.rule == "B01" }?.observedAt)
        XCTAssertEqual(report.ruleStatuses.first { $0.rule == "E01" }?.observedAt,
                       sample.addingTimeInterval(-8))
        XCTAssertNil(report.ruleStatuses.first { $0.rule == "D01" }?.observedAt)
    }
    func testExistingSessionSupervisorGenerationChangeIsScored() {
        let local = snapshot()
        let inactive = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false)
        XCTAssertEqual(inactive.first { $0.id == "F04" }?.status, .notApplicable)
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false,
            supervisorStaleObserved: true)
        let report = SafetyEvaluator.evaluate(rules)
        XCTAssertEqual(report.ruleStatuses.first { $0.rule == "F04" }?.status, "triggered")
        XCTAssertEqual(report.deductions.first { $0.ruleID == "F04" }?.points, 20)
        XCTAssertEqual(report.ruleStatuses.first { $0.rule == "F04" }?.observedAt, local.collectedAt)
        let clean = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false,
            supervisorStaleObserved: false)
        XCTAssertEqual(clean.first { $0.id == "F04" }?.status, .passed)
    }
    func testDNSRulesNameMissingRequestBoundPathAsCriticalUnknown() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false)
        for id in ["D01"] {
            XCTAssertEqual(rules.first { $0.id == id }?.status,
                           .unknown(source: "dns-path-unobserved", critical: true), id)
        }
        XCTAssertEqual(rules.first { $0.id == "D04" }?.status,
                       .unknown(source: "dns-encryption-policy", critical: true))
        for id in ["D02", "D03"] {
            XCTAssertEqual(rules.first { $0.id == id }?.status,
                           .unknown(source: "dns-resolver-geolocation", critical: true), id)
        }
        let report = SafetyEvaluator.evaluate(rules)
        for id in ["D01"] {
            XCTAssertEqual(report.ruleStatuses.first { $0.rule == id }?.source, "dns-path-unobserved", id)
        }
        XCTAssertEqual(report.ruleStatuses.first { $0.rule == "D04" }?.source, "dns-encryption-policy")
        for id in ["D02", "D03"] {
            XCTAssertEqual(report.ruleStatuses.first { $0.rule == id }?.source, "dns-resolver-geolocation", id)
        }
    }
    func testD01ComparesObservedResolverAgainstActiveResolverConfiguration() {
        let sampledAt = Date()
        func status(_ verdict: DNSPathEvidence.ResolverVerdict?,
                    observedAt: Date? = sampledAt) -> ObservationStatus? {
            EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
                reputation: nil, countryLanguages: nil, firstRun: false,
                dnsResolverVerdict: verdict, dnsPathObservedAt: observedAt)
                .first { $0.id == "D01" }?.status
        }
        XCTAssertEqual(status(.matchesConfiguredPath), .passed)
        XCTAssertEqual(status(.bypassesConfiguredPath), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(status(.unknown), .unknown(source: "dns-path-unobserved", critical: true))
        XCTAssertEqual(status(.matchesConfiguredPath, observedAt: nil),
                       .unknown(source: "dns-path-unobserved", critical: true))
        let observed = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false,
            dnsResolverVerdict: .bypassesConfiguredPath, dnsPathObservedAt: sampledAt)
        XCTAssertEqual(SafetyEvaluator.evaluate(observed).deductions.first { $0.ruleID == "D01" }?.points, 12)
    }
    func testD02AndD03ResolverCountryDifferencesAreScoredAndIncompleteEvidenceHolds() {
        let now = Date()
        let dns = DNSResolverCountryAssessment(httpConsistency: .differentWithUnknown,
            resolverConsistency: .different, httpObservedAt: now, resolverObservedAt: now)
        let observations = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false,
            dnsResolverCountryAssessment: dns)
        let result = SafetyEvaluator.evaluate(observations)
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "D02" }?.status, "triggeredUnknown")
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "D02" }?.source, "dns-resolver-geolocation")
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "D03" }?.status, "triggered")
        XCTAssertEqual(result.deductions.first { $0.ruleID == "D02" }?.points, 6)
        XCTAssertEqual(result.deductions.first { $0.ruleID == "D03" }?.points, 4)
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "D02" }?.observedAt, now)
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "D03" }?.observedAt, now)
    }

    func testD04ScoresExplicitCleartextAndOnlyPassesObservedEncryptedPolicy() {
        func report(_ security: DNSPathEvidence.ResolverSecurity?,
                    required: DNSRequiredProtocol = .anyEncrypted,
                    downgrade: Bool = false) -> SafetyEvaluation {
            let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
                reputation: nil, countryLanguages: nil, firstRun: false,
                dnsPathObservedAt: Date(), dnsResolverSecurity: security,
                dnsRequiredProtocol: required,
                dnsEncryptionDowngradeObserved: downgrade)
            return SafetyEvaluator.evaluate(rules)
        }
        let encrypted = report(.dnsOverHTTPS)
        XCTAssertEqual(encrypted.ruleStatuses.first { $0.rule == "D04" }?.status, "passed")

        let cleartextWithoutBaseline = report(.cleartext)
        XCTAssertEqual(cleartextWithoutBaseline.ruleStatuses.first { $0.rule == "D04" }?.status,
                       "triggered")
        XCTAssertEqual(cleartextWithoutBaseline.deductions.first { $0.ruleID == "D04" }?.points, 8)
        XCTAssertEqual(cleartextWithoutBaseline.decision, .hold)

        let protocolMismatch = report(.dnsOverTLS, required: .dnsOverHTTPS)
        XCTAssertEqual(protocolMismatch.ruleStatuses.first { $0.rule == "D04" }?.status, "triggered")
        XCTAssertEqual(protocolMismatch.deductions.first { $0.ruleID == "D04" }?.points, 8)

        let tlsAccepted = report(.dnsOverTLS, required: .anyEncrypted)
        XCTAssertEqual(tlsAccepted.ruleStatuses.first { $0.rule == "D04" }?.status, "passed")

        let downgrade = report(.dnsOverHTTPS, downgrade: true)
        XCTAssertEqual(downgrade.ruleStatuses.first { $0.rule == "D04" }?.status, "triggered")
        XCTAssertEqual(downgrade.deductions.first { $0.ruleID == "D04" }?.points, 8)

        let unavailable = report(.unknown)
        XCTAssertEqual(unavailable.ruleStatuses.first { $0.rule == "D04" }?.source,
                       "dns-encryption-policy")
        XCTAssertEqual(unavailable.decision, .hold)
    }

    func testDNSPathAndEncryptionEvidenceExpireAfterSpoolLifetime() {
        let local = snapshot()
        let now = local.collectedAt
        let observations = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false,
            dnsResolverVerdict: .matchesConfiguredPath,
            dnsPathObservedAt: now.addingTimeInterval(-DNSPathEvidenceSpool.maximumAge - 1),
            dnsResolverSecurity: .dnsOverHTTPS,
            at: now)
        let result = SafetyEvaluator.evaluate(observations)
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "D01" }?.status, "unknown")
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "D04" }?.status, "unknown")
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "D04" }?.source,
                       "dns-encryption-policy")
        XCTAssertEqual(result.decision, .hold)
    }
    func testC07IsNotApplicableWhenDisabledAndScoresOnlyVerifiedCountryComparison() {
        func status(_ comparison: Consistency?) -> ObservationStatus? {
            EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
                reputation: nil, countryLanguages: nil, firstRun: false,
                tcpUDPConsistency: comparison).first { $0.id == "C07" }?.status
        }
        XCTAssertEqual(status(nil), .notApplicable)
        XCTAssertEqual(status(.unknown), .unknown(source: "stun-country", critical: true))
        XCTAssertEqual(status(.different), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(status(.matching), .passed)
    }
    func testD07ScoresLegacyTLSMinimumAndKeepsUnreadableOptionsUnknown() {
        func status(_ value: Bool?) -> (ObservationStatus, SafetyEvaluation) {
            let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
                reputation: nil, countryLanguages: nil, firstRun: false,
                settingsTLSDowngradeAllowed: value)
            return (rules.first { $0.id == "D07" }!.status, SafetyEvaluator.evaluate(rules))
        }
        let downgraded = status(true)
        XCTAssertEqual(downgraded.0, .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(downgraded.1.deductions.first { $0.ruleID == "D07" }?.points, 15)
        XCTAssertEqual(status(false).0, .passed)
        XCTAssertEqual(status(nil).0, .unknown(source: "tls-options-unreadable", critical: true))
    }
    func testUnimplementedCollectorsReportTheSpecificRuleAndNeverLocalPaths() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: nil)
        for id in ["B06", "C05", "F03", "G03"] {
            XCTAssertEqual(rules.first { $0.id == id }?.status,
                .unknown(source: "collector-gap-\(id)", critical: true), id)
        }
        let report = SafetyEvaluator.evaluate(rules)
        for id in ["B06", "C05", "F03", "G03"] {
            XCTAssertEqual(report.ruleStatuses.first { $0.rule == id }?.source, "collector-gap-\(id)", id)
        }
        XCTAssertFalse(report.ruleStatuses.contains { $0.source?.contains("/") == true })
    }
    func testAutoMemoryDisabledAndEmptyIndexUseDistinctDeductions() {
        func deduction(disabled: Bool, empty: Bool?) -> Int? {
            let observations = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
                reputation: nil, countryLanguages: nil, firstRun: nil,
                autoMemoryDisabled: disabled, autoMemoryIndexEmpty: empty)
            let result = SafetyEvaluator.evaluate(observations)
            return result.deductions.first { $0.ruleID == "G07" }?.points
        }
        XCTAssertEqual(deduction(disabled: true, empty: nil), 2)
        XCTAssertEqual(deduction(disabled: false, empty: true), 1)
        XCTAssertNil(deduction(disabled: false, empty: false))
    }
    func testSecondClaudeInstallationIsScored() {
        let observations = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: nil,
            otherClaudeInstallationObserved: true)
        let result = SafetyEvaluator.evaluate(observations)
        XCTAssertEqual(result.deductions.first { $0.ruleID == "G05" }?.points, 6)
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "G05" }?.status, "triggered")
    }
    func testCompleteClaudeInstallationScanCanPassG05() {
        let observations = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: nil,
            otherClaudeInstallationObserved: false)
        let result = SafetyEvaluator.evaluate(observations)
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "G05" }?.status, "passed")
        XCTAssertFalse(result.deductions.contains { $0.ruleID == "G05" })
    }
    func testRepeatedAuthenticationContextSwitchesAreScored() {
        let observations = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: nil,
            authenticationContextStatus: .triggered(.standard, deduplicationKey: nil))
        let result = SafetyEvaluator.evaluate(observations)
        XCTAssertEqual(result.deductions.first { $0.ruleID == "G08" }?.points, 8)
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "G08" }?.status, "triggered")
    }
    func testModelLifecycleWatchlistScoresOnlyExplicitAttentionStatus() {
        let flagged = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: nil, modelAssessment: .attention)
        let flaggedResult = SafetyEvaluator.evaluate(flagged)
        XCTAssertEqual(flaggedResult.deductions.first { $0.ruleID == "G06" }?.points, 2)

        let active = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: nil, modelAssessment: .active)
        XCTAssertEqual(active.first { $0.id == "G06" }?.status, .passed)

        let unknown = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: nil, modelAssessment: .unknown)
        XCTAssertEqual(unknown.first { $0.id == "G06" }?.status,
                       .unknown(source: "model-lifecycle", critical: true))
    }
    func testExplicitTLSDisableAndProtectedBypassAreScored() {
        let local = LocalEnvironmentSnapshot.collect(
            environment: ["NODE_TLS_REJECT_UNAUTHORIZED": "0", "NO_PROXY": "api.anthropic.com"],
            systemTimeZone: TimeZone(identifier: "UTC")!, systemLocale: Locale(identifier: "en_US"),
            preferredLanguages: ["en"], targetHost: "api.anthropic.com", collectedAt: Date())
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
                                                        countryLanguages: nil, firstRun: nil)
        XCTAssertEqual(rules.first { $0.id == "D05" }?.status, .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "A07" }?.status, .triggered(.standard, deduplicationKey: nil))
        let result = SafetyEvaluator.evaluate(rules)
        XCTAssertTrue(result.deductions.contains { $0.ruleID == "D05" && $0.points == 35 })
        XCTAssertTrue(result.deductions.contains { $0.ruleID == "A07" && $0.points == 30 })
    }
    func testCustomCATrustConfigurationScoresF08AndUnknownStaysHold() {
        func status(_ configured: Bool?) -> (ObservationStatus?, SafetyEvaluation) {
            let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil,
                reputation: nil, countryLanguages: nil, firstRun: false,
                customTrustConfiguration: configured)
            return (rules.first { $0.id == "F08" }?.status, SafetyEvaluator.evaluate(rules))
        }
        let configured = status(true)
        XCTAssertEqual(configured.0, .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(configured.1.deductions.first { $0.ruleID == "F08" }?.points, 8)
        XCTAssertEqual(status(false).0, .passed)
        let unreadable = status(nil)
        XCTAssertEqual(unreadable.0, .unknown(source: "trust-config-unreadable", critical: true))
        XCTAssertEqual(unreadable.1.decision, .hold)
    }
    func testCrossTargetCountryDifferenceRequiresFreshCorrectlyBoundTrace() {
        let local = snapshot()
        let now = local.collectedAt
        let api = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let other = TraceProbeResult.observed(TraceObservation(targetHost: "claude.ai", ip: "192.0.2.2", countryCode: "JP"))
        func evaluate(_ item: TimedTrace) -> ObservationStatus? {
            EnvironmentAssessment.observations(snapshot: local, apiTrace: api, reputation: nil,
                countryLanguages: nil, firstRun: nil, traceObservedAt: now,
                additionalTraces: ["claude.ai": item], at: now).first { $0.id == "A04" }?.status
        }
        XCTAssertEqual(evaluate(TimedTrace(result: other, observedAt: now)), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(evaluate(TimedTrace(result: other, observedAt: now.addingTimeInterval(-6))),
                       .unknown(source: "collector-gap-A04", critical: true))
        let wrong = TraceProbeResult.observed(TraceObservation(targetHost: "other.example", ip: "192.0.2.2", countryCode: "JP"))
        XCTAssertEqual(evaluate(TimedTrace(result: wrong, observedAt: now)), .unknown(source: "collector-gap-A04", critical: true))
    }

    func testRequiredDestinationReachabilityNeedsCompleteFreshHostBoundTraces() {
        let local = snapshot()
        let now = local.collectedAt
        func trace(_ host: String, _ ip: String) -> TraceProbeResult {
            .observed(TraceObservation(targetHost: host, ip: ip, countryCode: "US"))
        }
        let api = trace(ClaudeTraceTarget.api.rawValue, "192.0.2.1")
        let login = TimedTrace(result: trace(ClaudeTraceTarget.claudeAI.rawValue, "192.0.2.2"),
                               observedAt: now)
        let platform = TimedTrace(result: trace(ClaudeTraceTarget.platform.rawValue, "192.0.2.3"),
                                  observedAt: now)

        func a10(apiTrace: TraceProbeResult?, apiAt: Date?,
                 login: TimedTrace?, platform: TimedTrace?) -> ObservationStatus? {
            var traces: [String: TimedTrace] = [:]
            if let login { traces[ClaudeTraceTarget.claudeAI.rawValue] = login }
            if let platform { traces[ClaudeTraceTarget.platform.rawValue] = platform }
            return EnvironmentAssessment.observations(snapshot: local,
                apiTrace: apiTrace, reputation: nil, countryLanguages: nil,
                firstRun: false, traceObservedAt: apiAt,
                additionalTraces: traces, at: now).first { $0.id == "A10" }?.status
        }

        XCTAssertEqual(a10(apiTrace: api, apiAt: now, login: login, platform: platform), .passed)
        let missingPlatform = a10(apiTrace: api, apiAt: now, login: login, platform: nil)
        XCTAssertEqual(missingPlatform, .triggeredAndUnknown(
            .standard, deduplicationKey: nil,
            source: "required-destination-trace", critical: true))
        XCTAssertEqual(a10(apiTrace: api, apiAt: now, login: login, platform: TimedTrace(
            result: platform.result, observedAt: now.addingTimeInterval(-6))),
            missingPlatform)
        XCTAssertEqual(a10(apiTrace: api, apiAt: now, login: login, platform: TimedTrace(
            result: trace("unexpected.example", "192.0.2.3"), observedAt: now)),
            missingPlatform)
        XCTAssertEqual(a10(apiTrace: api, apiAt: now, login: login, platform: TimedTrace(
            result: trace(ClaudeTraceTarget.platform.rawValue, "not-an-ip"), observedAt: now)),
            missingPlatform)
        XCTAssertEqual(a10(apiTrace: nil, apiAt: nil, login: login, platform: platform),
                       missingPlatform)
        XCTAssertEqual(a10(apiTrace: api, apiAt: now.addingTimeInterval(-6),
                           login: login, platform: platform), missingPlatform)

        let incomplete = EnvironmentAssessment.observations(snapshot: local, apiTrace: api,
            reputation: nil, countryLanguages: nil, firstRun: false, traceObservedAt: now,
            additionalTraces: [ClaudeTraceTarget.claudeAI.rawValue: login], at: now)
        let evaluation = SafetyEvaluator.evaluate(incomplete)
        XCTAssertEqual(evaluation.decision, .hold)
        XCTAssertEqual(evaluation.deductions.first { $0.ruleID == "A10" }?.points, 15)
        XCTAssertEqual(evaluation.deductions.first { $0.ruleID == "H01" }?.points, 20)
    }

    func testCrossTargetASNDifferenceRequiresMatchingFreshEvidence() {
        let local = snapshot()
        let now = local.collectedAt
        let api = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let other = TimedTrace(result: .observed(TraceObservation(targetHost: "claude.ai", ip: "192.0.2.2", countryCode: "US")), observedAt: now)
        func reputation(_ ip: String, _ asn: Int) -> IPReputation {
            IPReputation(ip: ip, countryCode: "US", timeZone: nil, autonomousSystem: asn,
                         isDatacenter: nil, isVPN: nil, isProxy: nil, isTor: nil, isAbuser: nil)
        }
        func result(_ otherIP: String, _ time: Date) -> ObservationStatus? {
            EnvironmentAssessment.observations(snapshot: local, apiTrace: api, reputation: reputation("192.0.2.1", 1),
                countryLanguages: nil, firstRun: nil, traceObservedAt: now, reputationObservedAt: now,
                additionalTraces: ["claude.ai": other],
                additionalReputations: ["claude.ai": TimedReputation(value: reputation(otherIP, 2), observedAt: time)],
                at: now).first { $0.id == "A05" }?.status
        }
        XCTAssertEqual(result("192.0.2.2", now), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(result("192.0.2.3", now), .unknown(source: "collector-gap-A05", critical: true))
        XCTAssertEqual(result("192.0.2.2", now.addingTimeInterval(-21_601)), .unknown(source: "collector-gap-A05", critical: true))
    }
    func testDualStackRequiresFreshDirectProbesOfBothFamilies() {
        let now = Date()
        let local = LocalEnvironmentSnapshot.collect(environment: [:], systemTimeZone: TimeZone(identifier: "UTC"),
            systemLocale: Locale(identifier: "en_US"), preferredLanguages: ["en"],
            targetHost: "api.anthropic.com", collectedAt: now)
        let v4 = TimedTrace(result: .observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US")), observedAt: now)
        func status(_ v6: TimedTrace) -> ObservationStatus? {
            EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
                countryLanguages: nil, firstRun: nil, ipv4Trace: v4, ipv6Trace: v6, at: now)
                .first { $0.id == "A06" }?.status
        }
        let v6 = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "2001:db8::1", countryCode: "US"))
        XCTAssertEqual(status(TimedTrace(result: v6, observedAt: now)), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(status(TimedTrace(result: v6, observedAt: now.addingTimeInterval(-6))), .unknown(source: "collector-gap-A06", critical: true))
        XCTAssertEqual(status(TimedTrace(result: .unknown(reason: "TRACE_REQUEST_FAILED"), observedAt: now)), .unknown(source: "collector-gap-A06", critical: true))
        XCTAssertEqual(status(v4), .unknown(source: "collector-gap-A06", critical: true))
    }
    func testObservedRepeatedProxyChangesAreScored() {
        let sampledAt = Date()
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, recentRouteChanges: 3,
            recentRouteChangesObservedAt: sampledAt)
        XCTAssertEqual(rules.first { $0.id == "C08" }?.status, .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "C08" }?.observedAt, sampledAt)
        let insufficient = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, recentRouteChanges: 2,
            recentRouteChangesObservedAt: sampledAt)
        XCTAssertEqual(insufficient.first { $0.id == "C08" }?.status, .unknown(source: "collector-gap-C08", critical: true))
        XCTAssertEqual(insufficient.first { $0.id == "C08" }?.observedAt, sampledAt)
        let stableWindow = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, recentRouteChanges: 2, routeChangeWindowCovered: true)
        XCTAssertEqual(stableWindow.first { $0.id == "C08" }?.status, .passed)
        let missingSampler = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, recentRouteChanges: nil, routeChangeWindowCovered: true)
        XCTAssertEqual(missingSampler.first { $0.id == "C08" }?.status,
                       .unknown(source: "collector-gap-C08", critical: true))
    }
    func testSessionLocaleChangesAreScored() {
        let local = snapshot()
        let changed = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, sessionLocaleChanged: true)
        XCTAssertEqual(changed.first { $0.id == "E10" }?.status, .triggered(.standard, deduplicationKey: nil))
        let same = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, sessionLocaleChanged: false)
        XCTAssertEqual(same.first { $0.id == "E10" }?.status, .passed)
        let unavailable = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil)
        XCTAssertEqual(unavailable.first { $0.id == "E10" }?.status, .unknown(source: "collector-gap-E10", critical: true))
    }
    func testUnexpectedInstalledExecutableIsScored() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, installedExecutableMatches: false)
        XCTAssertEqual(rules.first { $0.id == "F05" }?.status, .triggered(.standard, deduplicationKey: nil))
        let unverified = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, installedExecutableMatches: true)
        XCTAssertEqual(unverified.first { $0.id == "F05" }?.status, .unknown(source: "collector-gap-F05", critical: true))
    }
    func testExplicitWrapperConflictIsScoredAndForcesHold() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, officialWrapperMatches: false)
        XCTAssertEqual(rules.first { $0.id == "F06" }?.status, .triggered(.standard, deduplicationKey: nil))
        XCTAssertTrue(SafetyEvaluator.evaluate(rules).deductions.contains { $0.ruleID == "F06" })
    }
    func testUnmanagedClaudeIsScored() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, unmanagedClaudeObserved: true)
        XCTAssertEqual(rules.first { $0.id == "F07" }?.status, .triggered(.standard, deduplicationKey: nil))
        XCTAssertTrue(SafetyEvaluator.evaluate(rules).deductions.contains { $0.ruleID == "F07" })
    }
    func testCertificateVerificationFailureIsScored() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(),
            apiTrace: .unknown(reason: "CERTIFICATE_VERIFICATION_FAILED"), reputation: nil,
            countryLanguages: nil, firstRun: nil)
        XCTAssertEqual(rules.first { $0.id == "D06" }?.status, .triggered(.standard, deduplicationKey: nil))
        XCTAssertTrue(SafetyEvaluator.evaluate(rules).deductions.contains { $0.ruleID == "D06" })
    }
    func testSettingsOverridesAndExplicitTLSDisableAreScored() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, settingsRoutingOverride: true, settingsTLSDisabled: true)
        XCTAssertEqual(rules.first { $0.id == "F02" }?.status, .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "D05" }?.status, .triggered(.standard, deduplicationKey: nil))
    }
    func testAllProxyCaseVariantConflictsDeductF01() {
        let pairs: [(String, String)] = [
            ("http_proxy", "HTTP_PROXY"),
            ("https_proxy", "HTTPS_PROXY"),
            ("all_proxy", "ALL_PROXY"),
            ("no_proxy", "NO_PROXY"),
        ]
        for (lower, upper) in pairs {
            let local = LocalEnvironmentSnapshot.collect(
                environment: [
                    lower: "http://lower-user:lower-secret@lower.example:8080",
                    upper: "http://upper-user:upper-secret@upper.example:9090",
                ],
                systemTimeZone: TimeZone(identifier: "Asia/Shanghai"),
                systemLocale: Locale(identifier: "zh_CN"),
                preferredLanguages: ["zh-CN"],
                targetHost: "api.anthropic.com",
                collectedAt: Date()
            )
            XCTAssertEqual(local.conflictingProxyKeys, [lower, upper])
            XCTAssertFalse(String(reflecting: local).contains("lower-secret"))
            XCTAssertFalse(String(reflecting: local).contains("upper-secret"))
            let rules = EnvironmentAssessment.observations(
                snapshot: local, apiTrace: nil, reputation: nil,
                countryLanguages: nil, firstRun: false)
            XCTAssertEqual(rules.first { $0.id == "F01" }?.status,
                           .triggered(.standard, deduplicationKey: nil), "\(lower) / \(upper)")
            XCTAssertEqual(SafetyEvaluator.evaluate(rules).deductions.first { $0.ruleID == "F01" }?.points, 8)
        }
    }
    func testClaudeSettingsLocaleMismatchIsScored() {
        let local = LocalEnvironmentSnapshot.collect(
            environment: ["LANG": "en_US.UTF-8"],
            systemTimeZone: TimeZone(identifier: "Asia/Shanghai")!,
            systemLocale: Locale(identifier: "zh_CN"),
            preferredLanguages: ["zh-CN"], collectedAt: Date())
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil,
            settingsTimeZone: .different, settingsLanguage: .different,
            settingsLocaleOverride: .different)
        XCTAssertEqual(rules.first { $0.id == "E02" }?.status,
                       .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "E04" }?.status,
                       .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "E05" }?.status,
                       .triggered(.standard, deduplicationKey: nil))
    }
    func testLocaleOverrideIsScoredWithoutDoubleCountingTheSameField() {
        let local = LocalEnvironmentSnapshot.collect(
            environment: ["LANG": "en_US.UTF-8", "LC_ALL": "ja_JP.UTF-8"],
            systemTimeZone: TimeZone(identifier: "UTC")!, systemLocale: Locale(identifier: "en_US"),
            preferredLanguages: ["en-US"], targetHost: "api.anthropic.com", collectedAt: Date())
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
                                                        countryLanguages: nil, firstRun: nil)
        XCTAssertEqual(rules.first { $0.id == "E04" }?.status, .triggered(.standard, deduplicationKey: "field:process-locale"))
        XCTAssertEqual(rules.first { $0.id == "E05" }?.status, .triggered(.standard, deduplicationKey: "field:process-locale"))
        let result = SafetyEvaluator.evaluate(rules)
        XCTAssertEqual(result.deductions.filter { ["E04", "E05"].contains($0.ruleID) }.count, 1)
    }
    func testObservedManagedActivityUsesEscalationThresholds() {
        let local = snapshot()
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, managedSessionCount: 9, recentManagedStarts: 31)
        let result = SafetyEvaluator.evaluate(rules)
        XCTAssertTrue(result.deductions.contains { $0.ruleID == "G01" && $0.points == 16 })
        XCTAssertTrue(result.deductions.contains { $0.ruleID == "G02" && $0.points == 15 })
    }
    func testManagedSessionConcurrencyUsesLiveCountBudget() {
        let local = snapshot()
        func status(_ count: Int) -> ObservationStatus? {
            EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
                countryLanguages: nil, firstRun: nil, managedSessionCount: count)
                .first { $0.id == "G01" }?.status
        }
        XCTAssertEqual(status(4), .unknown(source: "collector-gap-G01", critical: true))
        XCTAssertEqual(status(5), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(status(8), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(status(9), .triggered(.elevated, deduplicationKey: nil))
    }
    func testManagedStartRateUsesRollingMinuteBudget() {
        let local = snapshot()
        func status(_ count: Int) -> ObservationStatus? {
            EnvironmentAssessment.observations(snapshot: local, apiTrace: nil, reputation: nil,
                countryLanguages: nil, firstRun: nil, recentManagedStarts: count)
                .first { $0.id == "G02" }?.status
        }
        XCTAssertEqual(status(10), .unknown(source: "collector-gap-G02", critical: true))
        XCTAssertEqual(status(11), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(status(30), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(status(31), .triggered(.elevated, deduplicationKey: nil))
    }
    func testMismatchedReputationDoesNotBecomeEvidence() {
        let reputation = IPReputation(ip: "192.0.2.2", countryCode: "US", timeZone: "America/New_York",
            autonomousSystem: 123, isDatacenter: false, isVPN: false, isProxy: false, isTor: false, isAbuser: false)
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: trace,
            reputation: reputation, countryLanguages: CountryLanguages(countryCode: "US", languages: ["en"]), firstRun: true, traceObservedAt: Date(), reputationObservedAt: Date())
        XCTAssertEqual(rules.first { $0.id == "B05" }?.status, .unknown(source: "reputation", critical: false))
    }
    func testProxyAndConflictingCountryRemainDistinct() {
        let reputation = IPReputation(ip: "192.0.2.1", countryCode: "US", timeZone: "America/New_York",
            autonomousSystem: 123, isDatacenter: false, isVPN: false, isProxy: true, isTor: false, isAbuser: false)
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "CN"))
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: trace,
            reputation: reputation, countryLanguages: CountryLanguages(countryCode: "US", languages: ["en"]), firstRun: false, traceObservedAt: Date(), reputationObservedAt: Date())
        XCTAssertEqual(rules.first { $0.id == "B03" }?.status, .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "B04" }?.status, .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "H03" }?.status, .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "E06" }?.status, .unknown(source: "region", critical: false))
    }

    func testIPAPIAbuseAndOpenProxySignalsAreBoundToFreshMatchingExit() {
        let local = snapshot()
        let trace = TraceProbeResult.observed(TraceObservation(
            targetHost: ClaudeTraceTarget.api.rawValue, ip: "192.0.2.1", countryCode: "US"))
        let positive = IPReputation(ip: "192.0.2.1", countryCode: nil, timeZone: nil,
            autonomousSystem: nil, isDatacenter: nil, isVPN: nil, isProxy: true, isTor: nil, isAbuser: true)
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
            reputation: nil, countryLanguages: nil, firstRun: false,
            securityReputation: positive, securityReputationObservedAt: local.collectedAt,
            traceObservedAt: local.collectedAt, at: local.collectedAt)
        XCTAssertEqual(rules.first { $0.id == "B02" }?.status,
                       .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "B03" }?.status,
                       .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(rules.first { $0.id == "B02" }?.observedAt, local.collectedAt)
        XCTAssertEqual(rules.first { $0.id == "B03" }?.observedAt, local.collectedAt)
        XCTAssertTrue(SafetyEvaluator.evaluate(rules).deductions.contains { $0.ruleID == "B02" && $0.points == 30 })

        let cleanAbuse = IPReputation(ip: "192.0.2.1", countryCode: nil, timeZone: nil,
            autonomousSystem: nil, isDatacenter: nil, isVPN: nil, isProxy: false, isTor: nil, isAbuser: false)
        let partial = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
            reputation: nil, countryLanguages: nil, firstRun: false,
            securityReputation: cleanAbuse, securityReputationObservedAt: local.collectedAt,
            traceObservedAt: local.collectedAt, at: local.collectedAt)
        XCTAssertEqual(partial.first { $0.id == "B02" }?.status, .passed)
        XCTAssertEqual(partial.first { $0.id == "B03" }?.status,
                       .unknown(source: "ipapi-is-open-proxy-only", critical: false))
    }

    func testIPAPIReputationCannotScoreForAnotherOrStaleExit() {
        let local = snapshot()
        let trace = TraceProbeResult.observed(TraceObservation(
            targetHost: ClaudeTraceTarget.api.rawValue, ip: "192.0.2.1", countryCode: "US"))
        let positive = IPReputation(ip: "192.0.2.2", countryCode: nil, timeZone: nil,
            autonomousSystem: nil, isDatacenter: nil, isVPN: nil, isProxy: true, isTor: nil, isAbuser: true)
        let mismatched = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
            reputation: nil, countryLanguages: nil, firstRun: false,
            securityReputation: positive, securityReputationObservedAt: local.collectedAt,
            securityReputationEnabled: true,
            traceObservedAt: local.collectedAt, at: local.collectedAt)
        XCTAssertEqual(mismatched.first { $0.id == "B02" }?.status,
                       .unknown(source: "ipapi-is-unavailable", critical: false))
        let stale = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace,
            reputation: nil, countryLanguages: nil, firstRun: false,
            securityReputation: IPReputation(ip: "192.0.2.1", countryCode: nil, timeZone: nil,
                autonomousSystem: nil, isDatacenter: nil, isVPN: nil, isProxy: true, isTor: nil, isAbuser: true),
            securityReputationObservedAt: local.collectedAt.addingTimeInterval(-21_601),
            securityReputationEnabled: true,
            traceObservedAt: local.collectedAt, at: local.collectedAt)
        XCTAssertEqual(stale.first { $0.id == "B02" }?.status,
                       .unknown(source: "ipapi-is-unavailable", critical: false))
    }

    func testWrongTargetAndUnvalidatedTZInheritanceAreUnknown() {
        let snapshot = LocalEnvironmentSnapshot.collect(environment: [:], systemTimeZone: TimeZone(identifier: "Asia/Shanghai")!,
            systemLocale: Locale(identifier: "zh_CN"), preferredLanguages: ["zh-CN"], collectedAt: Date())
        let reputation = IPReputation(ip: "192.0.2.1", countryCode: "US", timeZone: "America/New_York",
            autonomousSystem: 123, isDatacenter: false, isVPN: false, isProxy: false, isTor: false, isAbuser: false)
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "claude.ai", ip: "192.0.2.1", countryCode: "US"))
        let rules = EnvironmentAssessment.observations(snapshot: snapshot, apiTrace: trace,
            reputation: reputation, countryLanguages: CountryLanguages(countryCode: "US", languages: ["en"]), firstRun: false, traceObservedAt: Date(), reputationObservedAt: Date())
        XCTAssertEqual(rules.first { $0.id == "E02" }?.status, .unknown(source: "runtime-time-zone-inheritance", critical: true))
        XCTAssertEqual(rules.first { $0.id == "B05" }?.status, .unknown(source: "reputation", critical: false))
    }
    func testConfiguredProxyCannotBecomeCleanFromReputationAlone() {
        let local = LocalEnvironmentSnapshot.collect(environment: ["HTTPS_PROXY": "http://127.0.0.1:8000"],
            systemTimeZone: TimeZone(identifier: "Asia/Shanghai")!, systemLocale: Locale(identifier: "zh_CN"),
            preferredLanguages: ["zh-CN"], targetHost: "api.anthropic.com", collectedAt: Date())
        let reputation = IPReputation(ip: "192.0.2.1", countryCode: "US", timeZone: "America/New_York",
            autonomousSystem: 123, isDatacenter: false, isVPN: false, isProxy: false, isTor: false, isAbuser: false)
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace, reputation: reputation,
            countryLanguages: CountryLanguages(countryCode: "US", languages: ["en"]), firstRun: false, traceObservedAt: Date(), reputationObservedAt: Date())
        XCTAssertEqual(rules.first { $0.id == "B04" }?.status, .unknown(source: "reputation", critical: false))
    }
    func testDifferentTargetRouteCannotProveAPIDirect() {
        let local = LocalEnvironmentSnapshot.collect(environment: ["HTTPS_PROXY": "http://127.0.0.1:8000", "NO_PROXY": "claude.ai"],
            systemTimeZone: TimeZone(identifier: "Asia/Shanghai")!, systemLocale: Locale(identifier: "zh_CN"),
            preferredLanguages: ["zh-CN"], targetHost: "claude.ai", collectedAt: Date())
        let reputation = IPReputation(ip: "192.0.2.1", countryCode: "US", timeZone: "America/New_York",
            autonomousSystem: 123, isDatacenter: false, isVPN: false, isProxy: false, isTor: false, isAbuser: false)
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace, reputation: reputation,
            countryLanguages: CountryLanguages(countryCode: "US", languages: ["en"]), firstRun: false, traceObservedAt: Date(), reputationObservedAt: Date())
        XCTAssertEqual(rules.first { $0.id == "B04" }?.status, .unknown(source: "reputation", critical: false))
    }
    func testUnknownHistoryDoesNotAssumeFirstRun() {
        let rules = EnvironmentAssessment.observations(snapshot: snapshot(), apiTrace: nil, reputation: nil,
                                                        countryLanguages: nil, firstRun: nil)
        XCTAssertEqual(rules.first { $0.id == "H04" }?.status, .unknown(source: "history", critical: false))
    }
    func testStaleNetworkAndReputationEvidenceCannotPass() {
        let local = snapshot()
        let reputation = IPReputation(ip: "192.0.2.1", countryCode: "US", timeZone: "America/New_York",
            autonomousSystem: 123, isDatacenter: false, isVPN: false, isProxy: false, isTor: false, isAbuser: false)
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US"))
        let now = local.collectedAt
        for (traceDate, reputationDate) in [(now.addingTimeInterval(-6), now), (now, now.addingTimeInterval(-21_601)), (now.addingTimeInterval(1), now)] {
            let rules = EnvironmentAssessment.observations(snapshot: local, apiTrace: trace, reputation: reputation,
                countryLanguages: CountryLanguages(countryCode: "US", languages: ["en"]), firstRun: false,
                traceObservedAt: traceDate, reputationObservedAt: reputationDate, at: now)
            XCTAssertEqual(rules.first { $0.id == "B05" }?.status, .unknown(source: "reputation", critical: false))
        }
    }
}
