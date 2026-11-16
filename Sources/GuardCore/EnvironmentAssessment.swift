import Foundation

/// Converts collected facts into rule observations. Missing adapters remain
/// unknown; this is deliberately not a launch authorization by itself.
public struct CountryLanguages: Sendable {
    public let countryCode: String
    public let languages: [String]
    public init(countryCode: String, languages: [String]) {
        self.countryCode = countryCode.uppercased()
        self.languages = languages
    }
}

public struct TimedTrace: Sendable {
    public let result: TraceProbeResult
    public let observedAt: Date
    public init(result: TraceProbeResult, observedAt: Date) {
        self.result = result
        self.observedAt = observedAt
    }
}
public struct TimedReputation: Sendable {
    public let value: IPReputation
    public let observedAt: Date
    public init(value: IPReputation, observedAt: Date) {
        self.value = value
        self.observedAt = observedAt
    }
}
public enum EnvironmentAssessment {
    public static func observations(
        snapshot: LocalEnvironmentSnapshot,
        apiTrace: TraceProbeResult?,
        reputation: IPReputation?,
        countryLanguages: CountryLanguages?,
        firstRun: Bool?,
        proxyCheck: ProxyCheckObservation? = nil,
        securityReputation: IPReputation? = nil,
        securityReputationObservedAt: Date? = nil,
        securityReputationEnabled: Bool = false,
        proxyCheckObservedAt: Date? = nil,
        traceObservedAt: Date? = nil,
        reputationObservedAt: Date? = nil,
        additionalTraces: [String: TimedTrace] = [:],
        additionalReputations: [String: TimedReputation] = [:],
        ipv4Trace: TimedTrace? = nil,
        ipv6Trace: TimedTrace? = nil,
        tcpUDPConsistency: Consistency? = nil,
        tcpUDPObservedAt: Date? = nil,
        customEndpointPresent: Bool = false,
        historicalTriggers: [RuleObservation] = [],
        managedSessionCount: Int? = nil,
        recentManagedStarts: Int? = nil,
        recentRouteChanges: Int? = nil,
        recentRouteChangesObservedAt: Date? = nil,
        routeChangeWindowCovered: Bool = false,
        sessionLocaleChanged: Bool? = nil,
        sessionExit: SessionExitTracker.Observation? = nil,
        installedExecutableMatches: Bool? = nil,
        officialWrapperMatches: Bool? = nil,
        unmanagedClaudeObserved: Bool? = nil,
        otherClaudeInstallationObserved: Bool? = nil,
        clientCertificate: ClientCertificateStatus? = nil,
        clientCertificateConfigured: Bool? = nil,
        clientCertificateUnknown: Bool = false,
        settingsRoutingOverride: Bool = false,
        customTrustConfiguration: Bool? = nil,
        settingsTLSDisabled: Bool = false,
        autoMemoryDisabled: Bool? = nil,
        autoMemorySettingConflict: Bool = false,
        autoMemoryIndexEmpty: Bool? = nil,
        authenticationContextStatus: ObservationStatus? = nil,
        modelAssessment: ClaudeModelAssessment = .unknown,
        settingsTimeZone: Consistency? = nil,
        settingsLanguage: Consistency? = nil,
        settingsLocaleOverride: Consistency? = nil,
        settingsTLSDowngradeAllowed: Bool? = nil,
        effectiveProxyConfigured: Bool? = nil,
        supervisorStaleObserved: Bool? = nil,
        dnsResolverVerdict: DNSPathEvidence.ResolverVerdict? = nil,
        dnsPathObservedAt: Date? = nil,
        dnsResolverCountryAssessment: DNSResolverCountryAssessment? = nil,
        dnsResolverSecurity: DNSPathEvidence.ResolverSecurity? = nil,
        dnsRequiredProtocol: DNSRequiredProtocol = .anyEncrypted,
        dnsEncryptionDowngradeObserved: Bool = false,
        claudeFailureCounts: ClaudeFailureCounts? = nil,
        networkTimeStatus: NetworkTimeStatusSnapshot? = nil,
        at evaluationTime: Date = Date()
    ) -> [RuleObservation] {
        // Separate lifetimes prevent old network or provider facts being
        // renewed just by taking a fresh local snapshot.
        let age = evaluationTime.timeIntervalSince(snapshot.collectedAt)
        guard (0...5).contains(age) else {
        return SafetyRuleCatalog.ids.map {
                RuleObservation(id: $0, status: .unknown(source: "stale-snapshot", critical: true))
            }
        }
        var states = Dictionary(uniqueKeysWithValues: SafetyRuleCatalog.ids.map {
            ($0, ObservationStatus.unknown(source: "collector-gap-\($0)", critical: true))
        })
        if let networkTimeStatus {
            switch networkTimeStatus.value {
            case .enabled: states["E08"] = .passed
            case .disabled: states["E08"] = .triggered(.standard, deduplicationKey: nil)
            case .unavailable:
                states["E08"] = .unknown(source: "network-time-status-privileged", critical: true)
            }
        } else {
            states["E08"] = .unknown(source: "network-time-status-privileged", critical: true)
        }
        if let claudeFailureCounts {
            states["G03"] = claudeFailureCounts.apiFailuresInMinute > 10
                ? .triggered(.standard, deduplicationKey: nil) : .passed
            states["G04"] = claudeFailureCounts.authenticationFailuresInTenMinutes >= 3
                ? .triggered(.standard, deduplicationKey: nil) : .passed
        }
        if let tcpUDPConsistency {
            setConsistency("C07", tcpUDPConsistency, source: "stun-country", critical: true)
        } else {
            states["C07"] = .notApplicable
        }
        let dnsPathIsFresh = dnsPathObservedAt.map {
            (0...DNSPathEvidenceSpool.maximumAge).contains(evaluationTime.timeIntervalSince($0))
        } ?? false
        if dnsPathIsFresh {
            switch dnsResolverVerdict {
            case .matchesConfiguredPath:
                states["D01"] = .passed
            case .bypassesConfiguredPath:
                states["D01"] = .triggered(.standard, deduplicationKey: nil)
            case .unknown, .none:
                states["D01"] = .unknown(source: "dns-path-unobserved", critical: true)
            }
        } else {
            states["D01"] = .unknown(source: "dns-path-unobserved", critical: true)
        }
        func setDNSCountryRule(_ id: String, _ result: DNSResolverCountryResult) {
            switch result {
            case .notApplicable:
                states[id] = .notApplicable
            case .matching:
                states[id] = .passed
            case .different:
                states[id] = .triggered(.standard, deduplicationKey: nil)
            case .unknown:
                states[id] = .unknown(source: "dns-resolver-geolocation", critical: true)
            case .differentWithUnknown:
                states[id] = .triggeredAndUnknown(.standard, deduplicationKey: nil,
                    source: "dns-resolver-geolocation", critical: true)
            }
        }
        if let dnsResolverCountryAssessment {
            setDNSCountryRule("D02", dnsResolverCountryAssessment.httpConsistency)
            setDNSCountryRule("D03", dnsResolverCountryAssessment.resolverConsistency)
        } else {
            for id in ["D02", "D03"] {
                states[id] = .unknown(source: "dns-resolver-geolocation", critical: true)
            }
        }
        // Configured encryption policy and observed protocol downgrade are
        // separate from the resolver egress probe.
        if dnsEncryptionDowngradeObserved {
            states["D04"] = .triggered(.standard, deduplicationKey: nil)
        } else if dnsPathIsFresh {
            switch dnsResolverSecurity {
            case .dnsOverHTTPS:
                states["D04"] = dnsRequiredProtocol.accepts(.dnsOverHTTPS)
                    ? .passed
                    : .triggered(.standard, deduplicationKey: nil)
            case .dnsOverTLS:
                states["D04"] = dnsRequiredProtocol.accepts(.dnsOverTLS)
                    ? .passed
                    : .triggered(.standard, deduplicationKey: nil)
            case .encrypted:
                states["D04"] = dnsRequiredProtocol == .anyEncrypted
                    ? .passed
                    : .unknown(source: "dns-encryption-policy", critical: true)
            case .cleartext:
                states["D04"] = .triggered(.standard, deduplicationKey: nil)
            case .unknown, .none:
                states["D04"] = .unknown(source: "dns-encryption-policy", critical: true)
            }
        } else {
            states["D04"] = .unknown(source: "dns-encryption-policy", critical: true)
        }
        if effectiveProxyConfigured == false {
            states["A02"] = .notApplicable
        } else if effectiveProxyConfigured == true,
                  let traceObservedAt,
                  (0...5).contains(evaluationTime.timeIntervalSince(traceObservedAt)),
                  case .observed(let trace) = apiTrace,
                  trace.targetHost == ClaudeTraceTarget.api.rawValue {
            // A successful HTTPS trace through the effective Claude settings
            // proves the configured proxy completed CONNECT and TLS traffic.
            states["A02"] = .passed
        } else {
            states["A02"] = .unknown(source: "proxy-connectivity-unverified", critical: true)
        }
        func setConsistency(_ id: String, _ value: Consistency, source: String, critical: Bool = true) {
            switch value {
            case .matching: states[id] = .passed
            case .different: states[id] = .triggered(.standard, deduplicationKey: nil)
            case .notApplicable: states[id] = .notApplicable
            case .unknown: states[id] = .unknown(source: source, critical: critical)
            }
        }
        func setFlag(_ id: String, _ value: Bool?) {
            states[id] = value.map { $0 ? .triggered(.standard, deduplicationKey: nil) : .passed }
                ?? .unknown(source: "reputation", critical: false)
        }
        func conservativeMerge(_ left: Consistency, _ right: Consistency) -> Consistency {
            if left == .different || right == .different { return .different }
            if left == .unknown || right == .unknown { return .unknown }
            if left == .matching || right == .matching { return .matching }
            return .notApplicable
        }
        let processTimeZone: Consistency = snapshot.processTimeZoneIdentifier != nil
            ? snapshot.processTimeZoneConsistency : .unknown
        let effectiveTimeZone = settingsTimeZone.map { conservativeMerge(processTimeZone, $0) } ?? processTimeZone
        setConsistency("E02", effectiveTimeZone,
                       source: snapshot.processTimeZoneIdentifier == nil ? "runtime-time-zone-inheritance" : "process-time-zone")
        let effectiveLanguage = settingsLanguage.map {
            conservativeMerge(snapshot.processLanguageConsistency, $0)
        } ?? snapshot.processLanguageConsistency
        setConsistency("E04", effectiveLanguage, source: settingsLanguage == nil ? "process-locale" : "claude-settings-language")
        if snapshot.invalidProcessLocaleKeys.isEmpty,
           EnvironmentConsistency.localeOverride(environment: snapshot.processLocale) == .different {
            let sameField = snapshot.processLanguageConsistency == .different &&
                EnvironmentConsistency.language(local: snapshot.preferredLanguages.first,
                    expectedLanguages: snapshot.processLocale["LANG"].map { [$0] } ?? []) == .matching
            let key = sameField ? "field:process-locale" : nil
            if sameField { states["E04"] = .triggered(.standard, deduplicationKey: key) }
            states["E05"] = .triggered(.standard, deduplicationKey: key)
        }
        if let settingsLocaleOverride {
            let processOverride = EnvironmentConsistency.localeOverride(environment: snapshot.processLocale)
            let effectiveOverride = conservativeMerge(processOverride, settingsLocaleOverride)
            if effectiveOverride == .different {
                states["E05"] = .triggered(.standard, deduplicationKey: nil)
            } else if effectiveOverride == .unknown {
                states["E05"] = .unknown(source: "claude-settings-locale", critical: true)
            } else if snapshot.processLocale.isEmpty {
                states["E05"] = .passed
            }
        }
        states["F01"] = snapshot.conflictingProxyKeys.isEmpty
            ? .passed : .triggered(.standard, deduplicationKey: nil)
        if snapshot.explicitlyDisablesTLSVerification || settingsTLSDisabled {
            states["D05"] = .triggered(.standard, deduplicationKey: nil)
        }
        if let settingsTLSDowngradeAllowed {
            states["D07"] = settingsTLSDowngradeAllowed
                ? .triggered(.standard, deduplicationKey: nil) : .passed
        } else {
            states["D07"] = .unknown(source: "tls-options-unreadable", critical: true)
        }
        if settingsRoutingOverride {
            states["F02"] = .triggered(.standard, deduplicationKey: nil)
        }
        if let customTrustConfiguration {
            states["F08"] = customTrustConfiguration
                ? .triggered(.standard, deduplicationKey: nil) : .passed
        } else {
            states["F08"] = .unknown(source: "trust-config-unreadable", critical: true)
        }
        if autoMemorySettingConflict {
            states["G07"] = .unknown(source: "auto-memory-settings", critical: true)
        } else if autoMemoryDisabled == true {
            states["G07"] = .triggered(.elevated, deduplicationKey: nil)
        } else if autoMemoryDisabled == false, let autoMemoryIndexEmpty {
            states["G07"] = autoMemoryIndexEmpty
                ? .triggered(.standard, deduplicationKey: nil) : .passed
        } else {
            // Enabled memory requires a metadata-only index census before it
            // can pass; until then it remains a conservative hold.
            states["G07"] = .unknown(source: "auto-memory-index", critical: true)
        }
        if customEndpointPresent {
            states["A09"] = .triggered(.standard, deduplicationKey: nil)
        }
        if let count = managedSessionCount, count > 4 {
            states["G01"] = .triggered(count > 8 ? .elevated : .standard, deduplicationKey: nil)
        }
        if let count = recentManagedStarts, count > 10 {
            states["G02"] = .triggered(count > 30 ? .elevated : .standard, deduplicationKey: nil)
        }
        #if os(macOS)
        if ProcessInfo.processInfo.operatingSystemVersion.majorVersion < 13 {
            states["E09"] = .triggered(.standard, deduplicationKey: nil)
        } else if snapshot.hasRemoteShellContext || snapshot.isVirtualized == true {
            states["E09"] = .triggered(.standard, deduplicationKey: nil)
        } else {
            switch snapshot.isVirtualized {
            case true:
                states["E09"] = .triggered(.standard, deduplicationKey: nil)
            case false:
                states["E09"] = .passed
            case nil:
                states["E09"] = .unknown(source: "runtime-virtualization", critical: false)
            }
        }
        #else
        states["E09"] = .triggered(.standard, deduplicationKey: nil)
        #endif
        if let count = recentRouteChanges {
            if count >= 3 {
                states["C08"] = .triggered(.standard, deduplicationKey: nil)
            } else if routeChangeWindowCovered {
                states["C08"] = .passed
            }
        }
        if let supervisorStaleObserved {
            states["F04"] = supervisorStaleObserved
                ? .triggered(.standard, deduplicationKey: nil) : .passed
        } else {
            states["F04"] = .notApplicable
        }
        if let sessionLocaleChanged {
            states["E10"] = sessionLocaleChanged
                ? .triggered(.standard, deduplicationKey: nil) : .passed
        }
        if let sessionExit {
            states["C06"] = sessionExit.changed
                ? .triggered(.standard, deduplicationKey: sessionExit.eventKey) : .passed
        }
        if installedExecutableMatches == false {
            states["F05"] = .triggered(.standard, deduplicationKey: nil)
        }
        if officialWrapperMatches == false {
            states["F06"] = .triggered(.standard, deduplicationKey: nil)
        }
        if unmanagedClaudeObserved == true {
            states["F07"] = .triggered(.standard, deduplicationKey: nil)
        }
        if let otherClaudeInstallationObserved {
            states["G05"] = otherClaudeInstallationObserved
                ? .triggered(.standard, deduplicationKey: nil) : .passed
        }
        if let authenticationContextStatus {
            states["G08"] = authenticationContextStatus
        }
        switch modelAssessment {
        case .active:
            states["G06"] = .passed
        case .attention:
            states["G06"] = .triggered(.standard, deduplicationKey: nil)
        case .unknown:
            states["G06"] = .unknown(source: "model-lifecycle", critical: true)
        }
        if clientCertificateUnknown {
            if clientCertificate == .expired {
                states["D08"] = .triggeredAndUnknown(.elevated, deduplicationKey: nil,
                                                     source: "client-certificate-unverified", critical: true)
            } else if clientCertificate == .expiring {
                states["D08"] = .triggeredAndUnknown(.standard, deduplicationKey: nil,
                                                     source: "client-certificate-unverified", critical: true)
            } else {
                states["D08"] = .unknown(source: "client-certificate-unverified", critical: true)
            }
        } else if let clientCertificate {
            switch clientCertificate {
            case .expired: states["D08"] = .triggered(.elevated, deduplicationKey: nil)
            case .expiring: states["D08"] = .triggered(.standard, deduplicationKey: nil)
            case .valid: states["D08"] = .passed
            }
        } else if clientCertificateConfigured == false {
            states["D08"] = .notApplicable
        } else if clientCertificateConfigured == true {
            states["D08"] = .unknown(source: "client-certificate-unverified", critical: true)
        }
        for observation in historicalTriggers where ["C01", "C02", "C03", "C04", "C05"].contains(observation.id) {
            states[observation.id] = observation.status
        }
        // Different observed destination countries are useful risk evidence.
        // Matching environment-level probes alone cannot prove that all
        // Claude configuration scopes follow those paths.
        if case .observed(let api) = apiTrace, api.targetHost == ClaudeTraceTarget.api.rawValue,
           let traceObservedAt, (0...5).contains(evaluationTime.timeIntervalSince(traceObservedAt)),
           let apiCountry = api.countryCode {
            for target in [ClaudeTraceTarget.claudeAI, .platform] {
                guard let item = additionalTraces[target.rawValue],
                      (0...5).contains(evaluationTime.timeIntervalSince(item.observedAt)),
                      case .observed(let other) = item.result, other.targetHost == target.rawValue,
                      let country = other.countryCode else { continue }
                if country != apiCountry {
                    states["A04"] = .triggered(.standard, deduplicationKey: nil)
                }
                if country == apiCountry, let reputation, let reputationObservedAt,
                   (0...21_600).contains(evaluationTime.timeIntervalSince(reputationObservedAt)),
                   IPAddress.bytes(api.ip) == IPAddress.bytes(reputation.ip),
                   reputation.countryCode == apiCountry, let apiASN = reputation.autonomousSystem,
                   let otherReputation = additionalReputations[target.rawValue],
                   (0...21_600).contains(evaluationTime.timeIntervalSince(otherReputation.observedAt)),
                   IPAddress.bytes(other.ip) == IPAddress.bytes(otherReputation.value.ip),
                   otherReputation.value.countryCode == country,
                   let otherASN = otherReputation.value.autonomousSystem, apiASN != otherASN {
                    states["A05"] = .triggered(.standard, deduplicationKey: nil)
                }
            }
        }
        if case .observed(let api) = apiTrace, api.targetHost == ClaudeTraceTarget.api.rawValue,
           let traceObservedAt, (0...5).contains(evaluationTime.timeIntervalSince(traceObservedAt)),
           let clock = api.clock {
            states["E07"] = clock.status(at: evaluationTime)
        }
        if snapshot.proxyTargetHost == ClaudeTraceTarget.api.rawValue, snapshot.proxyTargetPort == 443,
           case .direct(let reason) = snapshot.proxyRoute, reason == "NO_PROXY" {
            states["A07"] = .triggered(.standard, deduplicationKey: nil)
        }
        // Independent direct probes demonstrate the presence of both address
        // families. A failed IPv6 request cannot establish that IPv6 is absent.
        if case .direct = snapshot.proxyRoute,
           snapshot.proxyTargetHost == ClaudeTraceTarget.api.rawValue, snapshot.proxyTargetPort == 443,
           let ipv4Trace, let ipv6Trace,
           (0...5).contains(evaluationTime.timeIntervalSince(ipv4Trace.observedAt)),
           (0...5).contains(evaluationTime.timeIntervalSince(ipv6Trace.observedAt)),
           case .observed(let v4) = ipv4Trace.result, case .observed(let v6) = ipv6Trace.result,
           v4.targetHost == ClaudeTraceTarget.api.rawValue, v6.targetHost == ClaudeTraceTarget.api.rawValue,
           IPAddress.bytes(v4.ip)?.first == 4, IPAddress.bytes(v6.ip)?.first == 6 {
            states["A06"] = .triggered(.standard, deduplicationKey: nil)
        }
        if case .unknown(let reason) = snapshot.proxyRoute, reason == "UNSUPPORTED_PROXY_SCHEME" {
            states["A08"] = .triggered(.standard, deduplicationKey: nil)
        }
        let requiredDestinationTraces: [(host: String, result: TraceProbeResult?, observedAt: Date?)] = [
            (ClaudeTraceTarget.api.rawValue, apiTrace, traceObservedAt),
            (ClaudeTraceTarget.claudeAI.rawValue,
             additionalTraces[ClaudeTraceTarget.claudeAI.rawValue]?.result,
             additionalTraces[ClaudeTraceTarget.claudeAI.rawValue]?.observedAt),
            (ClaudeTraceTarget.platform.rawValue,
             additionalTraces[ClaudeTraceTarget.platform.rawValue]?.result,
             additionalTraces[ClaudeTraceTarget.platform.rawValue]?.observedAt),
        ]
        let incompleteDestinationTrace = requiredDestinationTraces.contains { item in
            guard let observedAt = item.observedAt,
                  (0...5).contains(evaluationTime.timeIntervalSince(observedAt)),
                  case .observed(let observation) = item.result,
                  observation.targetHost == item.host,
                  IPAddress.bytes(observation.ip) != nil else {
                return true
            }
            return false
        }
        if incompleteDestinationTrace {
            states["A10"] = .triggeredAndUnknown(
                .standard, deduplicationKey: nil,
                source: "required-destination-trace", critical: true)
        } else {
            states["A10"] = .passed
        }
        let targetTraces = [apiTrace] + additionalTraces.values.map { Optional($0.result) }
        if targetTraces.contains(where: {
            if case .unknown(let reason) = $0 { return reason == "CERTIFICATE_VERIFICATION_FAILED" }
            return false
        }) {
            states["D06"] = .triggered(.standard, deduplicationKey: nil)
        }
        states["H01"] = .passed
        states["H02"] = .passed
        if let firstRun {
            states["H04"] = firstRun ? .triggered(.standard, deduplicationKey: nil) : .passed
        } else {
            states["H04"] = .unknown(source: "history", critical: false)
        }
        // These facts are only applied if the reputation record matches the
        // observed API egress; a different IP must never be used as evidence.
        if case .observed(let trace) = apiTrace, trace.targetHost == ClaudeTraceTarget.api.rawValue, let reputation,
           let traceObservedAt, let reputationObservedAt,
           (0...5).contains(evaluationTime.timeIntervalSince(traceObservedAt)),
           (0...21_600).contains(evaluationTime.timeIntervalSince(reputationObservedAt)),
           IPAddress.bytes(trace.ip) == IPAddress.bytes(reputation.ip) {
            setFlag("B01", reputation.isTor)
            setFlag("B02", reputation.isAbuser)
            // ipapi.is defines true as a known open proxy; false does not
            // rule out every other kind of high-sharing proxy.
            states["B03"] = reputation.isProxy == true
                ? .triggered(.standard, deduplicationKey: nil)
                : .unknown(source: "proxy-sharing", critical: false)
            let proxyOrVPN: Bool?
            if reputation.isProxy == true || reputation.isVPN == true { proxyOrVPN = true }
            else if reputation.isProxy == false && reputation.isVPN == false {
                // Configuration is not proof of the actual path. If a proxy is
                // configured, retain uncertainty until route equivalence is verified.
                if case .direct = snapshot.proxyRoute, snapshot.proxyTargetHost == ClaudeTraceTarget.api.rawValue,
                   snapshot.proxyTargetPort == 443 { proxyOrVPN = false }
                else { proxyOrVPN = nil }
            } else { proxyOrVPN = nil }
            setFlag("B04", proxyOrVPN)
            setFlag("B05", reputation.isDatacenter)
            let countryAgrees = trace.countryCode == nil || reputation.countryCode == nil ||
                trace.countryCode == reputation.countryCode
            if !countryAgrees {
                states["H03"] = .triggered(.standard, deduplicationKey: nil)
            }
            if countryAgrees, let country = reputation.countryCode {
                switch RegionPolicy.classify(countryCode: country, at: evaluationTime) {
                case .supported: states["A01"] = .passed
                case .unsupported: states["A01"] = .triggered(.standard, deduplicationKey: nil)
                case .unknown: states["A01"] = .unknown(source: "region-policy", critical: true)
                }
            }
            if countryAgrees, let zone = reputation.timeZone, let systemZone = snapshot.systemTimeZoneIdentifier,
               let local = TimeZone(identifier: systemZone) {
                setConsistency("E01", EnvironmentConsistency.timeZone(local: local, expectedIdentifiers: [zone]),
                               source: "reputation", critical: false)
            } else {
                states["E01"] = .unknown(source: "reputation-location", critical: false)
            }
            if countryAgrees, let languages = countryLanguages, let country = reputation.countryCode,
               languages.countryCode == country {
                setConsistency("E03", EnvironmentConsistency.language(local: snapshot.preferredLanguages.first,
                                                                        expectedLanguages: languages.languages),
                               source: "country-languages", critical: false)
            } else {
                states["E03"] = .unknown(source: "country-languages", critical: false)
            }
            if countryAgrees, let country = reputation.countryCode, let region = snapshot.systemRegionCode {
                states["E06"] = country == region ? .passed : .triggered(.standard, deduplicationKey: nil)
            } else {
                states["E06"] = .unknown(source: "region", critical: false)
            }
        } else {
            for id in ["B01", "B02", "B03", "B04", "B05", "E01", "E03", "E06"] {
                states[id] = .unknown(source: "reputation", critical: false)
            }
        }
        let freshSecurityReputation: IPReputation? = {
            guard case .observed(let trace) = apiTrace,
                  trace.targetHost == ClaudeTraceTarget.api.rawValue,
                  let securityReputation, let securityReputationObservedAt,
                  (0...5).contains(evaluationTime.timeIntervalSince(traceObservedAt ?? .distantPast)),
                  (0...21_600).contains(evaluationTime.timeIntervalSince(securityReputationObservedAt)),
                  IPAddress.bytes(trace.ip) == IPAddress.bytes(securityReputation.ip) else { return nil }
            return securityReputation
        }()
        if securityReputationEnabled, freshSecurityReputation == nil {
            if case .triggered = states["B02"] {
                // Preserve positive data from another enabled reputation provider.
            } else {
                states["B02"] = .unknown(source: "ipapi-is-unavailable", critical: false)
            }
            if case .triggered = states["B03"] {
                // Preserve positive data from another enabled reputation provider.
            } else {
                states["B03"] = .unknown(source: "ipapi-is-unavailable", critical: false)
            }
        }
        if let securityReputation = freshSecurityReputation {
            if securityReputation.isAbuser != nil {
                setFlag("B02", securityReputation.isAbuser)
            } else if case .triggered = states["B02"] {
                // Keep positive evidence from another provider.
            } else {
                states["B02"] = .unknown(source: "ipapi-is", critical: false)
            }
            if securityReputation.isProxy == true {
                states["B03"] = .triggered(.standard, deduplicationKey: nil)
            } else if case .triggered = states["B03"] {
                // A negative result from one provider cannot erase another provider's positive label.
            } else {
                states["B03"] = .unknown(source: "ipapi-is-open-proxy-only", critical: false)
            }
        }
        // proxycheck.io has a separate, versioned detection schema. Its
        // aggregate risk includes its detection signals; declare only those
        // covered labels when asking the evaluator to deduplicate.
        if case .observed(let trace) = apiTrace, trace.targetHost == ClaudeTraceTarget.api.rawValue,
           let observation = proxyCheck, !observation.warning,
           IPAddress.bytes(trace.ip) == IPAddress.bytes(observation.ip),
           let traceObservedAt, let proxyCheckObservedAt,
           (0...5).contains(evaluationTime.timeIntervalSince(traceObservedAt)),
           (0...21_600).contains(evaluationTime.timeIntervalSince(proxyCheckObservedAt)) {
            func providerFlag(_ id: String, _ value: Bool?) {
                guard let value else {
                    // An unavailable second source must not erase an observed
                    // risk from the first source.
                    if case .triggered = states[id] { return }
                    if case .passed = states[id] { return }
                    states[id] = .unknown(source: "proxycheck", critical: false)
                    return
                }
                if case .triggered = states[id], !value {
                    states["H03"] = .triggered(.standard, deduplicationKey: nil)
                    return
                }
                if case .passed = states[id], value {
                    states["H03"] = .triggered(.standard, deduplicationKey: nil)
                }
                states[id] = value
                    ? .triggered(.standard, deduplicationKey: "provider:proxycheck") : .passed
            }
            providerFlag("B01", observation.isTor)
            providerFlag("B05", observation.isHosting)
            providerFlag("B06", observation.isAnonymous)
            // The response fetch time does not refresh the provider's
            // underlying IP record. B07 only uses source data updated within
            // the same fifteen-minute window as the provider cache.
            let providerDataIsFresh = observation.sourceDataUpdatedAt.map {
                let age = evaluationTime.timeIntervalSince($0)
                return (-5...ProxyCheckV3.maximumResultAge).contains(age)
            } == true
            let highDeviceSharingEstimate = providerDataIsFresh && (observation.estimatedDevicesAtAddress.map {
                $0 >= ProxyCheckV3.highAddressDeviceEstimateThreshold
            } == true)
            if providerDataIsFresh &&
                (observation.operatorOffersResidentialProxies == true || highDeviceSharingEstimate) {
                states["B07"] = .triggeredAndUnknown(.standard,
                    deduplicationKey: "provider:proxycheck",
                    source: "proxycheck-p2p-unobserved", critical: false)
            } else {
                // An absent residential-operator label cannot establish that
                // the IP is not a P2P proxy. Keep the composite rule unknown.
                states["B07"] = .unknown(source: "proxycheck-p2p-unobserved", critical: false)
            }
            let hasProxy: Bool?
            if observation.isVPN == true || observation.isProxy == true { hasProxy = true }
            else if observation.isVPN == false && observation.isProxy == false,
                    case .direct = snapshot.proxyRoute,
                    snapshot.proxyTargetHost == ClaudeTraceTarget.api.rawValue,
                    snapshot.proxyTargetPort == 443 { hasProxy = false }
            else { hasProxy = nil }
            providerFlag("B04", hasProxy)
            if let risk = observation.risk {
                states["B08"] = .triggered(.trustScore(100 - risk),
                    deduplicationKey: "provider:proxycheck|covers:B01,B04,B05,B06")
            } else {
                states["B08"] = .unknown(source: "proxycheck", critical: false)
            }
            switch observation.hasAttacks {
            case true:
                switch states["B02"] {
                case .some(.passed):
                    states["H03"] = .triggered(.standard, deduplicationKey: nil)
                    states["B02"] = .triggered(.standard, deduplicationKey: nil)
                case .some(.unknown(let source, let critical)):
                    if securityReputationEnabled {
                        states["B02"] = .triggeredAndUnknown(
                            .standard, deduplicationKey: nil, source: source, critical: critical
                        )
                    } else {
                        states["B02"] = .triggered(.standard, deduplicationKey: nil)
                    }
                case .some(.triggered), .some(.triggeredAndUnknown):
                    break
                case .some(.notApplicable), .some(.unsupported), .none:
                    states["B02"] = .triggered(.standard, deduplicationKey: nil)
                }
            case false:
                switch states["B02"] {
                case .some(.triggered), .some(.triggeredAndUnknown):
                    states["H03"] = .triggered(.standard, deduplicationKey: nil)
                case .some(.unknown) where securityReputationEnabled:
                    break
                case .some(.unsupported), .some(.notApplicable):
                    break
                default:
                    states["B02"] = .passed
                }
            case nil:
                if case .some(.unknown) = states["B02"], !securityReputationEnabled {
                    states["B02"] = .unknown(source: "proxycheck-attack-history", critical: false)
                }
            }
        }
        var sampledAt: [String: Date] = [:]
        if let dnsPathObservedAt { sampledAt["D01"] = dnsPathObservedAt }
        if let dnsPathObservedAt, dnsResolverSecurity != nil || dnsEncryptionDowngradeObserved {
            sampledAt["D04"] = dnsPathObservedAt
        }
        if let dnsResolverCountryAssessment {
            sampledAt["D02"] = dnsResolverCountryAssessment.httpObservedAt
            sampledAt["D03"] = dnsResolverCountryAssessment.resolverObservedAt
        }
        for id in ["A07", "A08", "A09", "D05", "D07", "E02", "E04", "E05", "E09",
                   "F01", "F02", "F05", "F06", "F07", "F08", "G01", "G02",
                   "G05", "G07", "G08"] {
            sampledAt[id] = snapshot.collectedAt
        }
        if clientCertificateConfigured != nil || clientCertificate != nil || clientCertificateUnknown {
            sampledAt["D08"] = snapshot.collectedAt
        }
        if supervisorStaleObserved != nil { sampledAt["F04"] = snapshot.collectedAt }
        if let networkTimeStatus { sampledAt["E08"] = networkTimeStatus.observedAt }
        if let geoSampledAt = historicalTriggers.first(where: { $0.id == "C05" })?.observedAt {
            sampledAt["C05"] = geoSampledAt
        }
        if let reputationObservedAt {
            for id in ["A01", "E01", "E03", "E06"] {
                sampledAt[id] = reputationObservedAt
            }
        }
        if let securityReputation, let securityReputationObservedAt,
           case .observed(let trace) = apiTrace,
           trace.targetHost == ClaudeTraceTarget.api.rawValue,
           (0...5).contains(evaluationTime.timeIntervalSince(traceObservedAt ?? .distantPast)),
           (0...21_600).contains(evaluationTime.timeIntervalSince(securityReputationObservedAt)),
           IPAddress.bytes(trace.ip) == IPAddress.bytes(securityReputation.ip) {
            sampledAt["B02"] = securityReputationObservedAt
            sampledAt["B03"] = securityReputationObservedAt
        }
        if case .observed(let trace) = apiTrace, trace.targetHost == ClaudeTraceTarget.api.rawValue,
           let proxyCheck, !proxyCheck.warning,
           IPAddress.bytes(trace.ip) == IPAddress.bytes(proxyCheck.ip),
           let traceObservedAt, (0...5).contains(evaluationTime.timeIntervalSince(traceObservedAt)),
           let proxyCheckObservedAt,
           (0...21_600).contains(evaluationTime.timeIntervalSince(proxyCheckObservedAt)) {
            for id in ["B01", "B02", "B04", "B05", "B06", "B07", "B08"] {
                sampledAt[id] = proxyCheckObservedAt
            }
        }
        if let traceObservedAt {
            for id in ["D06", "E07"] { sampledAt[id] = traceObservedAt }
        }
        if let oldestRequiredTrace = requiredDestinationTraces.compactMap(\.observedAt).min() {
            sampledAt["A10"] = oldestRequiredTrace
        }
        if let tcpUDPObservedAt { sampledAt["C07"] = tcpUDPObservedAt }
        if recentRouteChanges != nil, let recentRouteChangesObservedAt {
            sampledAt["C08"] = recentRouteChangesObservedAt
        }
        if let ipv4Trace, let ipv6Trace {
            sampledAt["A06"] = min(ipv4Trace.observedAt, ipv6Trace.observedAt)
        }
        if let traceObservedAt, !additionalTraces.isEmpty {
            sampledAt["A04"] = min(traceObservedAt, additionalTraces.values.map(\.observedAt).min() ?? traceObservedAt)
            if let reputationObservedAt {
                sampledAt["A05"] = min(sampledAt["A04"] ?? traceObservedAt, reputationObservedAt)
            }
        }
        return SafetyRuleCatalog.ids.map {
            RuleObservation(id: $0, status: states[$0]!, observedAt: sampledAt[$0])
        }
    }
}
