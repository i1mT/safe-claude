import Foundation
import Darwin

/// A point-in-time assessment for the environment passed by a launcher.
/// Network secrets remain in memory and are never included in the result.
public enum CurrentAssessment {
    public static let environmentKeys = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY",
        "no_proxy", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "CLAUDE_CODE_CERT_STORE", "CLAUDE_CODE_CLIENT_CERT",
        "CLAUDE_CODE_CLIENT_KEY", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_USE_SYSTEM_CA",
        "TZ", "LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE", "CLAUDE_CODE_PROCESS_WRAPPER",
        "HOME", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
        "CLAUDE_CODE_PROJECT_DIR_NAME",
        "ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_MODEL",
        "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]
    public static func captureEnvironment() -> [String: String] {
        var values: [String: String] = [:]
        for key in environmentKeys {
            if let value = getenv(key) { values[key] = String(cString: value) }
        }
        return values
    }
    /// Lightweight runtime check; a failure forces a full reassessment.
    public static func sessionExitChanged(environment: [String: String], tracker: SessionExitTracker,
                                          networkEpoch: Int, networkFingerprint: Data) async -> Bool? {
        let filtered = environment.filter { environmentKeys.contains($0.key) }
        let timed = await TraceCache.shared.observe(target: .api, environment: filtered, epoch: networkEpoch,
                                                    fingerprint: networkFingerprint)
        guard (0...5).contains(Date().timeIntervalSince(timed.observedAt)),
              case .observed(let trace) = timed.result, trace.targetHost == ClaudeTraceTarget.api.rawValue else {
            return nil
        }
        return await tracker.differsFromBaseline(ip: trace.ip)
    }

    public static func collect(environment: [String: String], useProxyCheck: Bool = false,
                               proxyCheckKey: String? = nil, minimumScore: Int = 80,
                               ipAPIKey: String? = nil,
                               allowIPWho: Bool = false, customEndpointPresent: Bool = false,
                               trustedEndpoints: [String] = [],
                               enableUDPCheck: Bool = false, stunEndpoint: String = STUNProbe.defaultEndpoint,
                               historyTracker: HistoryTracker? = nil, managedSessionCount: Int? = nil,
                               recentManagedStarts: Int? = nil, networkEpoch: Int? = nil,
                               networkFingerprint: Data? = nil, recentRouteChanges: Int? = nil,
                               recentRouteChangesObservedAt: Date? = nil,
                               routeChangeWindowCovered: Bool = false,
                               sessionLocaleChanged: Bool? = nil,
                               sessionExitTracker: SessionExitTracker? = nil,
                               installedExecutableMatches: Bool? = nil,
                               officialWrapperMatches: Bool? = nil,
                               unmanagedClaudeObserved: Bool? = nil,
                               otherClaudeInstallationObserved: Bool? = nil,
                               trackAuthenticationContext: Bool = false,
                               processAuthenticationContext: String? = nil,
                               authenticationContextTracker: AuthenticationContextTracker? = nil,
                               workingDirectory: String? = nil,
                               additionalSettingsPath: String? = nil,
                               commandLineSettings: SelectiveSettings.Findings? = nil,
                               commandLineRoutingEnvironment: [String: String] = [:],
                               commandLineRoutingConflict: Bool = false,
                               supervisorStaleObserved: Bool? = nil,
                               dnsResolverVerdict: DNSPathEvidence.ResolverVerdict? = nil,
                               dnsPathObservedAt: Date? = nil,
                               dnsResolverEndpoints: [DNSResolverEndpoint]? = nil,
                               dnsPathEvidence: DNSPathEvidence? = nil,
                               dnsRequiredProtocol: DNSRequiredProtocol = .anyEncrypted,
                               dnsEncryptionDowngradeObserved: Bool = false,
                               claudeFailureCounts: ClaudeFailureCounts? = nil) async -> SafetyEvaluation {
        let filtered = environment.filter { environmentKeys.contains($0.key) }
        async let settings = Task.detached {
            SelectiveSettings.inspectContext(environment: filtered, workingDirectory: workingDirectory,
                additionalSettingsPath: additionalSettingsPath,
                commandLineRoutingEnvironment: commandLineRoutingEnvironment,
                trustedEndpoints: trustedEndpoints)
        }.value
        let settingsInspection = await settings
        var settingsRoutingEnvironment = settingsInspection.routingEnvironment
        for (key, value) in commandLineRoutingEnvironment {
            settingsRoutingEnvironment[key] = value
        }
        let probeSettingsEnvironment = settingsRoutingEnvironment
        let settingsRoutingConflict = settingsInspection.routingConflict || commandLineRoutingConflict
        let effectiveProxyConfigured: Bool? = {
            guard !settingsRoutingConflict else { return nil }
            switch ProxyConfiguration.resolve(targetHost: ClaudeTraceTarget.api.rawValue,
                                              environment: filtered,
                                              settingsEnvironment: probeSettingsEnvironment) {
            case .proxy: return true
            case .direct: return false
            case .unknown: return nil
            }
        }()
        func observe(_ target: ClaudeTraceTarget, family: IPFamily = .automatic) async -> TimedTrace {
            guard !settingsRoutingConflict else {
                return TimedTrace(result: .unknown(reason: "SETTINGS_PROXY_CONFLICT"), observedAt: Date())
            }
            if let networkEpoch, let networkFingerprint {
                return await TraceCache.shared.observe(target: target, environment: filtered,
                    epoch: networkEpoch, fingerprint: networkFingerprint,
                    settingsEnvironment: probeSettingsEnvironment, family: family)
            }
            let probeSettings = probeSettingsEnvironment
            return await Task.detached {
                let result = TraceProbe.observe(target, environment: environment.filter { environmentKeys.contains($0.key) },
                    settingsEnvironment: probeSettings, family: family)
                return TimedTrace(result: result, observedAt: Date())
            }.value
        }
        func observeOther(_ target: ClaudeTraceTarget) async -> (TimedTrace, TimedReputation?) {
            let timed = await observe(target)
            guard allowIPWho, case .observed(let observed) = timed.result,
                  observed.targetHost == target.rawValue else { return (timed, nil) }
            let (value, date) = await IPWhoCache.shared.observe(ip: observed.ip, environment: filtered,
                                                                settingsEnvironment: probeSettingsEnvironment)
            guard let value, let date else { return (timed, nil) }
            return (timed, TimedReputation(value: value, observedAt: date))
        }
        async let api = observe(.api)
        async let login = observeOther(.claudeAI)
        async let platform = observeOther(.platform)
        async let ipv4 = observe(.api, family: .ipv4)
        async let ipv6 = observe(.api, family: .ipv6)
        async let dnsResolverSamples: [DNSResolverCountrySample] = {
            guard allowIPWho, let networkEpoch, let networkFingerprint,
                  let dnsResolverEndpoints, !dnsResolverEndpoints.isEmpty,
                  dnsResolverEndpoints.count <= DNSResolverEgressCache.maximumResolvers else { return [] }
            return await DNSResolverEgressCache.shared.observe(dnsResolverEndpoints,
                networkEpoch: networkEpoch, networkFingerprint: networkFingerprint,
                environment: filtered, settingsEnvironment: probeSettingsEnvironment)
        }()
        let stunTask: Task<STUNObservation?, Never>? = enableUDPCheck
            ? Task.detached(priority: .utility) { await STUNCache.shared.observe(endpoint: stunEndpoint) }
            : nil
        let apiResult = await api
        let trace = apiResult.result
        let traceAt = apiResult.observedAt
        var resolverSamples = await dnsResolverSamples
        if let dnsPathEvidence, let country = dnsPathEvidence.resolverCountryCode,
           let observedAt = dnsPathEvidence.resolverCountryObservedAt {
            resolverSamples.append(DNSResolverCountrySample(
                resolverDigest: dnsPathEvidence.resolverCountryResolverDigest ??
                    dnsPathEvidence.resolverDigest,
                countryCode: country, observedAt: observedAt))
        }
        let dnsCountryAssessment = DNSResolverCountryAssessment.evaluate(
            samples: resolverSamples,
            configuredResolverDigests: dnsResolverEndpoints?.map(\.digest),
            observedResolverDigest: dnsPathEvidence?.resolverDigest,
            targetHTTPCountry: {
                guard case .observed(let trace) = trace,
                      trace.targetHost == ClaudeTraceTarget.api.rawValue else { return nil }
                return trace.countryCode
            }(),
            targetHTTPObservedAt: traceAt)
        var reputation: IPReputation?
        var reputationAt: Date?
        var securityReputation: IPReputation?
        var securityReputationAt: Date?
        var proxy: ProxyCheckObservation?
        var proxyAt: Date?
        if case .observed(let observation) = trace {
            async let geo: (IPReputation?, Date?) = {
                guard allowIPWho else { return (nil, nil) }
                return await IPWhoCache.shared.observe(ip: observation.ip, environment: filtered,
                                                       settingsEnvironment: probeSettingsEnvironment)
            }()
            async let check: (ProxyCheckObservation?, Date?) = {
                guard useProxyCheck else { return (nil, nil) }
                return await ProxyCheckCache.shared.observe(ip: observation.ip, apiKey: proxyCheckKey,
                    environment: filtered, settingsEnvironment: probeSettingsEnvironment)
            }()
            async let security: (IPReputation?, Date?) = {
                guard let ipAPIKey else { return (nil, nil) }
                return await IPAPICache.shared.observe(ip: observation.ip, key: ipAPIKey,
                    environment: filtered, settingsEnvironment: probeSettingsEnvironment)
            }()
            (reputation, reputationAt) = await geo
            (proxy, proxyAt) = await check
            (securityReputation, securityReputationAt) = await security
        }
        let tcpUDPConsistency: Consistency?
        var tcpUDPObservedAt: Date?
        if enableUDPCheck {
            if !allowIPWho {
                tcpUDPConsistency = .unknown
            } else {
                let stun = await stunTask?.value
                tcpUDPObservedAt = stun?.observedAt
                if case .observed = trace,
                   (0...5).contains(Date().timeIntervalSince(traceAt)),
                   let stun,
                   (0...5).contains(Date().timeIntervalSince(stun.observedAt)),
                   case let geoResult = await IPWhoCache.shared.observe(ip: stun.mappedAddress,
                       environment: filtered, settingsEnvironment: probeSettingsEnvironment),
                   let udpGeo = geoResult.0, let udpGeoAt = geoResult.1,
                   (0...21_600).contains(Date().timeIntervalSince(udpGeoAt)),
                   (0...21_600).contains(Date().timeIntervalSince(reputationAt ?? .distantPast)),
                   let tcpCountry = reputation?.countryCode,
                   let udpCountry = udpGeo.countryCode {
                    tcpUDPConsistency = tcpCountry == udpCountry ? .matching : .different
                } else {
                    tcpUDPConsistency = .unknown
                }
            }
        } else {
            tcpUDPConsistency = nil
        }
        let (loginResult, platformResult) = await (login, platform)
        let (ipv4Result, ipv6Result) = await (ipv4, ipv6)
        let extra = [ClaudeTraceTarget.claudeAI.rawValue: loginResult.0,
                     ClaudeTraceTarget.platform.rawValue: platformResult.0]
        var extraReputations: [String: TimedReputation] = [:]
        extraReputations[ClaudeTraceTarget.claudeAI.rawValue] = loginResult.1
        extraReputations[ClaudeTraceTarget.platform.rawValue] = platformResult.1
        let snapshot = LocalEnvironmentSnapshot.capture(environment: filtered, targetHost: ClaudeTraceTarget.api.rawValue)
        let networkTimeStatus = NetworkTimeStatus.read(now: snapshot.collectedAt)
        var settingsFindings = settingsInspection.findings
        settingsFindings.merge(SelectiveSettings.modelEnvironment(filtered))
        if let commandLineSettings {
            settingsFindings.merge(commandLineSettings)
            // Claude's explicit --settings document is the most specific
            // settings layer for this invocation.
            if let disabled = commandLineSettings.autoMemoryDisabled {
                settingsFindings.autoMemoryDisabled = disabled
                settingsFindings.conflictingAutoMemorySetting =
                    commandLineSettings.conflictingAutoMemorySetting
            }
            if commandLineSettings.customAutoMemoryDirectory {
                settingsFindings.customAutoMemoryDirectory = true
                settingsFindings.autoMemoryIndexEmpty = commandLineSettings.autoMemoryIndexEmpty
                settingsFindings.conflictingAutoMemorySetting =
                    commandLineSettings.conflictingAutoMemorySetting
            }
        }
        let modelStatus: ClaudeModelAssessment = settingsFindings.invalidModelIdentifier ||
            settingsFindings.modelIdentifiers.count != 1
            ? .unknown
            : ClaudeModelLifecycle.assess(settingsFindings.modelIdentifiers, at: snapshot.collectedAt)
        if let inherited = filtered["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] {
            switch inherited.lowercased() {
            case "1", "true", "yes", "on":
                settingsFindings.autoMemoryDisabled = true
                settingsFindings.conflictingAutoMemorySetting = false
            case "0", "false", "no", "off":
                settingsFindings.autoMemoryDisabled = false
                settingsFindings.conflictingAutoMemorySetting = false
            default:
                settingsFindings.autoMemoryDisabled = nil
                settingsFindings.conflictingAutoMemorySetting = true
            }
        }
        let authenticationContextStatus: ObservationStatus?
        if trackAuthenticationContext {
            let context = settingsFindings.invalidAuthenticationMode ? nil :
                AuthenticationContext.combine(processMode: processAuthenticationContext,
                                              settingsModes: settingsFindings.authenticationModes)
            if let authenticationContextTracker {
                authenticationContextStatus = await authenticationContextTracker.observe(context)
            } else {
                authenticationContextStatus = .unknown(source: "auth-context", critical: true)
            }
        } else {
            authenticationContextStatus = nil
        }
        let hasCustomEndpoint = customEndpointPresent || settingsFindings.customEndpoint
        let settingsTimeZone: Consistency? = {
            guard !settingsFindings.invalidLocaleKeys.contains("TZ") else { return .unknown }
            guard let zone = settingsFindings.locale["TZ"] else { return nil }
            guard let systemZone = snapshot.systemTimeZoneIdentifier.flatMap(TimeZone.init(identifier:)) else {
                return .unknown
            }
            return EnvironmentConsistency.processTimeZone(environment: ["TZ": zone], system: systemZone,
                                                           at: snapshot.collectedAt)
        }()
        let localeKeys = ["LC_ALL", "LC_MESSAGES", "LANG"]
        let settingsLanguage: Consistency? = {
            if !settingsFindings.invalidLocaleKeys.isDisjoint(with: localeKeys) { return .unknown }
            guard localeKeys.contains(where: { settingsFindings.locale[$0] != nil }) else { return nil }
            return EnvironmentConsistency.processLanguage(environment: settingsFindings.locale,
                preferredLanguages: snapshot.preferredLanguages)
        }()
        let settingsLocaleOverride: Consistency? = {
            if !settingsFindings.invalidLocaleKeys.isDisjoint(with: ["LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE"]) {
                return .unknown
            }
            guard settingsFindings.locale["LANG"] != nil ||
                    ["LC_ALL", "LC_MESSAGES", "LC_CTYPE"].contains(where: { settingsFindings.locale[$0] != nil })
            else { return nil }
            return EnvironmentConsistency.localeOverride(environment: settingsFindings.locale)
        }()
        var certificateStatuses = settingsFindings.clientCertificateStatuses
        var invalidClientCertificate = settingsFindings.invalidClientCertificate
        let directCertificateConfigured = filtered["CLAUDE_CODE_CLIENT_CERT"] != nil
        if let path = filtered["CLAUDE_CODE_CLIENT_CERT"] {
            if let status = ClientCertificate.inspect(path: path, at: snapshot.collectedAt) {
                certificateStatuses.insert(status)
            } else {
                invalidClientCertificate = true
            }
        }
        let certificateStatus: ClientCertificateStatus?
        if certificateStatuses.contains(.expired) { certificateStatus = .expired }
        else if certificateStatuses.contains(.expiring) { certificateStatus = .expiring }
        else if certificateStatuses.contains(.valid) { certificateStatus = .valid }
        else { certificateStatus = nil }
        if certificateStatuses.count > 1 { invalidClientCertificate = true }
        let clientCertificateConfigured = directCertificateConfigured ||
            settingsFindings.clientCertificatesConfigured
        let trustKeys = ["NODE_EXTRA_CA_CERTS", "CLAUDE_CODE_CERT_STORE", "SSL_CERT_FILE",
                         "SSL_CERT_DIR", "NODE_USE_SYSTEM_CA"]
        let trustConfigurationPresent = settingsFindings.customTrustConfiguration ||
            trustKeys.contains { filtered[$0] != nil }
        let trustConfigurationStatus: Bool? = trustConfigurationPresent
            ? true : (settingsFindings.invalidTrustConfiguration ? nil : false)
        let tlsDowngradeStatus: Bool? = settingsFindings.invalidTLSOptions
            ? nil : settingsFindings.tlsDowngradeAllowed
        let languages = reputation?.countryCode.flatMap { CountryLanguageCatalog.languages(for: $0) }
        var history: HistoryTracker.Summary?
        var sessionExit: SessionExitTracker.Observation?
        if let sessionExitTracker, !hasCustomEndpoint, case .observed(let observation) = trace,
           observation.targetHost == ClaudeTraceTarget.api.rawValue,
           (0...5).contains(snapshot.collectedAt.timeIntervalSince(traceAt)) {
            sessionExit = await sessionExitTracker.observe(ip: observation.ip, at: snapshot.collectedAt)
        }
        if let historyTracker, !hasCustomEndpoint, case .observed(let observation) = trace,
           (0...5).contains(snapshot.collectedAt.timeIntervalSince(traceAt)) {
            history = await historyTracker.observe(environment: filtered, trace: observation,
                                                   reputation: reputation, at: snapshot.collectedAt)
        }
        let observations = EnvironmentAssessment.observations(snapshot: snapshot, apiTrace: trace,
            reputation: reputation, countryLanguages: languages, firstRun: history?.firstRun,
            proxyCheck: proxy, securityReputation: securityReputation,
            securityReputationObservedAt: securityReputationAt,
            securityReputationEnabled: ipAPIKey != nil,
            proxyCheckObservedAt: proxyAt, traceObservedAt: traceAt,
            reputationObservedAt: reputationAt, additionalTraces: extra, additionalReputations: extraReputations,
            ipv4Trace: ipv4Result, ipv6Trace: ipv6Result,
            tcpUDPConsistency: tcpUDPConsistency,
            tcpUDPObservedAt: tcpUDPObservedAt,
            customEndpointPresent: hasCustomEndpoint, historicalTriggers: history?.observations ?? [],
            managedSessionCount: managedSessionCount, recentManagedStarts: recentManagedStarts,
            recentRouteChanges: recentRouteChanges,
            recentRouteChangesObservedAt: recentRouteChangesObservedAt,
            routeChangeWindowCovered: routeChangeWindowCovered,
            sessionLocaleChanged: sessionLocaleChanged,
            sessionExit: sessionExit, installedExecutableMatches: installedExecutableMatches,
            officialWrapperMatches: officialWrapperMatches, unmanagedClaudeObserved: unmanagedClaudeObserved,
            otherClaudeInstallationObserved: otherClaudeInstallationObserved,
            clientCertificate: certificateStatus,
            clientCertificateConfigured: clientCertificateConfigured,
            clientCertificateUnknown: invalidClientCertificate,
            settingsRoutingOverride: settingsFindings.routingOverride,
            customTrustConfiguration: trustConfigurationStatus,
            settingsTLSDisabled: settingsFindings.tlsDisabled,
            autoMemoryDisabled: settingsFindings.autoMemoryDisabled,
            autoMemorySettingConflict: settingsFindings.conflictingAutoMemorySetting,
            autoMemoryIndexEmpty: settingsFindings.autoMemoryIndexEmpty,
            authenticationContextStatus: authenticationContextStatus,
            modelAssessment: modelStatus,
            settingsTimeZone: settingsTimeZone, settingsLanguage: settingsLanguage,
            settingsLocaleOverride: settingsLocaleOverride,
            settingsTLSDowngradeAllowed: tlsDowngradeStatus,
            effectiveProxyConfigured: effectiveProxyConfigured,
            supervisorStaleObserved: supervisorStaleObserved,
            dnsResolverVerdict: dnsResolverVerdict,
            dnsPathObservedAt: dnsPathObservedAt,
            dnsResolverCountryAssessment: dnsCountryAssessment,
            dnsResolverSecurity: dnsPathEvidence?.resolverSecurity,
            dnsRequiredProtocol: dnsRequiredProtocol,
            dnsEncryptionDowngradeObserved: dnsEncryptionDowngradeObserved,
            claudeFailureCounts: claudeFailureCounts,
            networkTimeStatus: networkTimeStatus)
        return SafetyEvaluator.evaluate(observations, minimumScore: minimumScore,
                                        warningScore: max(90, minimumScore))
    }

}
