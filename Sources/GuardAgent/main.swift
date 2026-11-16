import Darwin
import Foundation
import GuardCore
import Network
import AppKit

actor AgentState {
    private struct FailureEvidence {
        let identity: ProcessIdentity
        let sessionDigest: String
    }
    var last = GuardResponse(decision: "hold", reason: "尚未完成环境检查。")
    var fault: String?
    var recovering = true
    var lastLaunch: GuardResponse?
    var pending: [pid_t: Bool] = [:]
    var sessionStatuses: [pid_t: GuardResponse] = [:]
    var dnsEvidenceByPID: [pid_t: DNSPathEvidence] = [:]
    var dnsEncryptionDowngradeByPID: Set<pid_t> = []
    private var failureEvidenceByPID: [pid_t: FailureEvidence] = [:]
    var activeRequests = 0
    var draining = false
    var stoppingUnmanaged = false
    func get() -> GuardResponse {
        guard fault == nil, !recovering, !draining, !stoppingUnmanaged else { return last }
        if let active = SessionStatusSelection.worst(Array(sessionStatuses.values)) { return active }
        if let lastLaunch, (0...300).contains(Date().timeIntervalSince(lastLaunch.checkedAt)) {
            return lastLaunch
        }
        return last
    }
    func setLaunch(_ response: GuardResponse) { lastLaunch = response }
    func setSession(_ pid: pid_t, response: GuardResponse) { sessionStatuses[pid] = response }
    func sessionStatusSnapshot() -> [pid_t: GuardResponse] { sessionStatuses }
    func removeSession(_ pid: pid_t) {
        sessionStatuses.removeValue(forKey: pid)
        dnsEvidenceByPID.removeValue(forKey: pid)
        dnsEncryptionDowngradeByPID.remove(pid)
        failureEvidenceByPID.removeValue(forKey: pid)
    }
    func recordDNS(_ evidence: DNSPathEvidence, downgradeObserved: Bool = false) {
        if downgradeObserved { dnsEncryptionDowngradeByPID.insert(evidence.pid) }
        var accepted = evidence
        if evidence.resolverCountryCode == nil,
           let previous = dnsEvidenceByPID[evidence.pid],
           previous.resolverDigest == evidence.resolverDigest,
           previous.pidVersion == evidence.pidVersion,
           previous.processStartSeconds == evidence.processStartSeconds,
           previous.processStartMicroseconds == evidence.processStartMicroseconds,
           previous.resolverCountryCode != nil,
           let countryAt = previous.resolverCountryObservedAt,
           (0...DNSResolverEgressCache.lifetime).contains(Date().timeIntervalSince(countryAt)) {
            accepted = evidence.carryingResolverCountry(from: previous)
        }
        dnsEvidenceByPID[evidence.pid] = accepted
    }
    func dnsEvidence(_ pid: pid_t) -> DNSPathEvidence? {
        dnsEvidenceByPID[pid]
    }
    func dnsEncryptionDowngradeObserved(_ pid: pid_t) -> Bool {
        dnsEncryptionDowngradeByPID.contains(pid)
    }
    func recordFailureEvidence(pid: pid_t, identity: ProcessIdentity, sessionDigest: String) {
        failureEvidenceByPID[pid] = FailureEvidence(identity: identity, sessionDigest: sessionDigest)
    }
    func failureSessionDigest(pid: pid_t, identity: ProcessIdentity) -> String? {
        guard let evidence = failureEvidenceByPID[pid], evidence.identity == identity else { return nil }
        return evidence.sessionDigest
    }
    func set(_ response: GuardResponse) {
        if let fault { last = GuardResponse(decision: "hold", reason: fault) }
        else if recovering { last = GuardResponse(decision: "hold", reason: "正在恢复受管会话。") }
        else if draining { last = GuardResponse(decision: "hold", reason: "正在准备卸载。") }
        else { last = response }
    }
    func fail(_ reason: String) { fault = reason; last = GuardResponse(decision: "hold", reason: reason) }
    func finishRecovery() { recovering = false }
    func isHealthy() -> Bool { fault == nil && !recovering && !draining }
    func canMonitorUnmanaged() -> Bool { !recovering && !draining }
    func invalidate() {
        let pending = GuardResponse(decision: "hold", reason: "环境已变化，正在重新检查。")
        sessionStatuses = sessionStatuses.mapValues { _ in pending }
        dnsEvidenceByPID.removeAll()
        set(pending)
    }
    func beginUnmanagedStop() -> Bool {
        guard !recovering, !draining, !stoppingUnmanaged else { return false }
        stoppingUnmanaged = true
        set(GuardResponse(decision: "hold", reason: "发现未受管 Claude 进程，正在结束会话。",
            findings: [GuardFinding(rule: "F07", points: SafetyRuleCatalog.weights["F07"] ?? 15)]))
        return true
    }
    func endUnmanagedStop() { stoppingUnmanaged = false; invalidate() }
    func reserve(_ pid: pid_t, topLevel: Bool) -> Int? {
        guard fault == nil, !recovering, !draining, pending[pid] == nil else { return nil }
        pending[pid] = topLevel
        return pending.values.filter { $0 }.count
    }
    func release(_ pid: pid_t) { pending.removeValue(forKey: pid) }
    func acquireRequest() -> Bool {
        guard activeRequests < 32 else { return false }
        activeRequests += 1
        return true
    }
    func finishRequest() { activeRequests -= 1 }
    func beginDrain() -> Int { draining = true; set(last); return pending.count + (stoppingUnmanaged ? 1 : 0) }
    func cancelDrain() { draining = false }
}
actor NetworkEpoch {
    private var value = 0
    func advance() { value &+= 1 }
    func current() -> Int { value }
}
actor TicketRegistry {
    struct Entry: Sendable {
        let identity: ProcessIdentity
        let epoch: Int
        let fingerprint: Data
        let policy: GuardPolicy
        let settingsPaths: [String]
        let settingsFingerprint: Data
        let isTopLevel: Bool
        let deadline: TimeInterval
        let response: GuardResponse
    }
    private var entries: [String: Entry] = [:]
    func issue(identity: ProcessIdentity, epoch: Int, fingerprint: Data, policy: GuardPolicy,
               settingsPaths: [String], settingsFingerprint: Data, isTopLevel: Bool, response: GuardResponse) -> String? {
        let now = ProcessInfo.processInfo.systemUptime
        entries = entries.filter { $0.value.deadline > now }
        guard entries.count < 128 else { return nil }
        let token = UUID().uuidString
        entries[token] = Entry(identity: identity, epoch: epoch, fingerprint: fingerprint, policy: policy, settingsPaths: settingsPaths, settingsFingerprint: settingsFingerprint, isTopLevel: isTopLevel,
                               deadline: now + 1, response: response)
        return token
    }
    func consume(_ token: String, identity: ProcessIdentity, epoch: Int, fingerprint: Data, policy: GuardPolicy) -> (GuardResponse, Bool)? {
        guard let entry = entries.removeValue(forKey: token),
              entry.deadline > ProcessInfo.processInfo.systemUptime,
              entry.identity == identity, entry.epoch == epoch, entry.fingerprint == fingerprint,
              entry.policy == policy,
              systemFingerprint.captureSettings(paths: entry.settingsPaths) == entry.settingsFingerprint else { return nil }
        return (entry.response, entry.isTopLevel)
    }
}
func visibleFindings(_ result: SafetyEvaluation) -> [GuardFinding] {
    let totals = Dictionary(grouping: result.deductions.filter { $0.points > 0 }, by: \.ruleID)
        .mapValues { $0.reduce(0) { $0 + $1.points } }
    return totals.keys.sorted().map { GuardFinding(rule: $0, points: totals[$0]!) }
}
func visibleRuleStatuses(_ result: SafetyEvaluation) -> [RuleReportStatus] { result.ruleStatuses }
func validSettingsFindings(_ findings: SelectiveSettings.Findings?) -> Bool {
    guard let findings else { return true }
    let allowed = Set(["TZ", "LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE"])
    return findings.locale.count <= allowed.count && Set(findings.locale.keys).isSubset(of: allowed) &&
        findings.locale.values.allSatisfy { $0.utf8.count <= 256 && !$0.utf8.contains(0) } &&
        findings.invalidLocaleKeys.isSubset(of: allowed) &&
        (!findings.conflictingAutoMemorySetting || findings.autoMemoryDisabled == nil) &&
        findings.authenticationModes.count <= AuthenticationContext.modes.count &&
        findings.authenticationModes.isSubset(of: AuthenticationContext.modes) &&
        findings.clientCertificateStatuses.count <= 3 &&
        (findings.clientCertificatesConfigured || findings.clientCertificateStatuses.isEmpty) &&
        findings.modelIdentifiers.count <= 8 &&
        findings.modelIdentifiers.allSatisfy(ClaudeModelLifecycle.isValidIdentifier)
}
func assess(environment: [String: String], minimumScore: Int, allowIPWho: Bool,
            allowProxyCheck: Bool = false,
            enableUDPCheck: Bool = false, stunEndpoint: String = STUNProbe.defaultEndpoint,
            customEndpointPresent: Bool = false, historyTracker: HistoryTracker? = nil,
            trustedEndpoints: [String] = [],
            managedSessionCount: Int? = nil, recentManagedStarts: Int? = nil,
            networkEpoch: Int? = nil, networkFingerprint: Data? = nil,
            sessionLocaleChanged: Bool? = nil, sessionExitTracker: SessionExitTracker? = nil,
            installedExecutableMatches: Bool? = nil, officialWrapperMatches: Bool? = nil,
            unmanagedClaudeObserved: Bool? = nil, otherClaudeInstallationObserved: Bool? = nil,
            trackAuthenticationContext: Bool = false, processAuthenticationContext: String? = nil,
            authenticationContextTracker: AuthenticationContextTracker? = nil,
            workingDirectory: String? = nil,
            additionalSettingsPath: String? = nil,
            commandLineSettings: SelectiveSettings.Findings? = nil,
            commandLineRoutingEnvironment: [String: String] = [:],
            commandLineRoutingConflict: Bool = false,
            supervisorStaleObserved: Bool? = nil,
            dnsPathEvidence: DNSPathEvidence? = nil,
            dnsRequiredProtocol: DNSRequiredProtocol = .anyEncrypted,
            dnsEncryptionDowngradeObserved: Bool = false,
            claudeFailureCounts: ClaudeFailureCounts? = nil) async -> SafetyEvaluation {
    let key = try? GuardSecrets.readProxyCheckKey()
    let ipAPIKey = try? GuardSecrets.readIPAPIKey()
    await routeChanges.observe(systemFingerprint.captureRouteConfiguration())
    let recentRouteChanges = await routeChanges.count()
    let recentRouteChangesObservedAt = recentRouteChanges.map { _ in Date() }
    let isRouteChangeWindowCovered = await routeChanges.windowCovered()
    let dnsResolverEndpoints = systemFingerprint.activeDNSResolvers()
    let dnsResolverVerdict = dnsPathEvidence.map {
        $0.resolverVerdict(configuredResolverDigests: dnsResolverEndpoints.map {
            Set($0.map(\.digest))
        })
    }
    return await CurrentAssessment.collect(environment: environment, useProxyCheck: allowProxyCheck,
                                           proxyCheckKey: key, minimumScore: minimumScore, ipAPIKey: ipAPIKey,
                                           allowIPWho: allowIPWho,
                                           customEndpointPresent: customEndpointPresent,
                                           trustedEndpoints: trustedEndpoints,
                                           enableUDPCheck: enableUDPCheck, stunEndpoint: stunEndpoint,
                                           historyTracker: historyTracker,
                                           managedSessionCount: managedSessionCount, recentManagedStarts: recentManagedStarts,
                                           networkEpoch: networkEpoch, networkFingerprint: networkFingerprint,
                                           recentRouteChanges: recentRouteChanges,
                                           recentRouteChangesObservedAt: recentRouteChangesObservedAt,
                                           routeChangeWindowCovered: isRouteChangeWindowCovered,
                                           sessionLocaleChanged: sessionLocaleChanged,
                                           sessionExitTracker: sessionExitTracker,
                                           installedExecutableMatches: installedExecutableMatches,
                                           officialWrapperMatches: officialWrapperMatches,
                                           unmanagedClaudeObserved: unmanagedClaudeObserved,
                                           otherClaudeInstallationObserved: otherClaudeInstallationObserved,
                                           trackAuthenticationContext: trackAuthenticationContext,
                                           processAuthenticationContext: processAuthenticationContext,
                                           authenticationContextTracker: authenticationContextTracker,
                                           workingDirectory: workingDirectory,
                                           additionalSettingsPath: additionalSettingsPath,
                                           commandLineSettings: commandLineSettings,
                                           commandLineRoutingEnvironment: commandLineRoutingEnvironment,
                                           commandLineRoutingConflict: commandLineRoutingConflict,
                                           supervisorStaleObserved: supervisorStaleObserved,
                                           dnsResolverVerdict: dnsResolverVerdict,
                                           dnsPathObservedAt: dnsPathEvidence?.observedAt,
                                           dnsResolverEndpoints: dnsResolverEndpoints,
                                           dnsPathEvidence: dnsPathEvidence,
                                           dnsRequiredProtocol: dnsRequiredProtocol,
                                           dnsEncryptionDowngradeObserved: dnsEncryptionDowngradeObserved,
                                           claudeFailureCounts: claudeFailureCounts)
}

let agentArguments = CommandLine.arguments
let socketPath = agentArguments.count == 3 && agentArguments[1] == "--socket" ? agentArguments[2] : GuardIPC.socketPath
let networkEpoch = NetworkEpoch()
let tickets = TicketRegistry()
let state = AgentState()
let historyKeyData = socketPath == GuardIPC.socketPath ? try? GuardSecrets.historyKey() : nil
let systemFingerprint: SystemFingerprint = {
    if let historyKeyData, let fingerprint = try? SystemFingerprint(keyData: historyKeyData) {
        return fingerprint
    }
    return SystemFingerprint()
}()
let routeChanges: RouteChangeTracker = {
    let path = URL(fileURLWithPath: socketPath).deletingLastPathComponent()
        .appendingPathComponent("route-changes.json").path
    if socketPath == GuardIPC.socketPath, let historyKeyData,
       let tracker = try? RouteChangeTracker(persistentPath: path, keyData: historyKeyData) {
        return tracker
    }
    return RouteChangeTracker()
}()
let launchRateTracker = try? LaunchRateTracker(
    path: URL(fileURLWithPath: socketPath).deletingLastPathComponent()
        .appendingPathComponent("launch-rate.json").path)
let wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
    forName: NSWorkspace.didWakeNotification, object: NSWorkspace.shared, queue: nil
) { _ in
    Task {
        await routeChanges.resetContinuity()
        await networkEpoch.advance()
        await state.invalidate()
    }
}
let pathMonitor = NWPathMonitor()
pathMonitor.pathUpdateHandler = { _ in Task { await networkEpoch.advance(); await state.invalidate() } }
pathMonitor.start(queue: DispatchQueue(label: "safeclaude.network"))
let authenticationContextTracker = AuthenticationContextTracker(path:
    URL(fileURLWithPath: socketPath).deletingLastPathComponent()
        .appendingPathComponent("auth-context.json").path)
let claudeFailureTracker = ClaudeFailureTracker(path:
    URL(fileURLWithPath: socketPath).deletingLastPathComponent()
        .appendingPathComponent("claude-failures.json").path)
let policyPath = URL(fileURLWithPath: socketPath).deletingLastPathComponent().appendingPathComponent("policy.json").path
let journalPath = URL(fileURLWithPath: socketPath).deletingLastPathComponent().appendingPathComponent("sessions.json").path
let installedTargetFile = ProcessIdentity.read(getpid()).map {
    URL(fileURLWithPath: $0.executable).deletingLastPathComponent().appendingPathComponent("claude-target").path
}
func installedTargetMatches(_ executable: String, topLevel: Bool) -> Bool? {
    guard topLevel, let installedTargetFile else { return nil }
    guard let pathMatches = InstalledClaude.matches(requestedExecutable: executable, targetFile: installedTargetFile)
    else { return nil }
    guard pathMatches else { return false }
    let identityFile = URL(fileURLWithPath: installedTargetFile).deletingLastPathComponent()
        .appendingPathComponent("claude-identity.json").path
    return InstalledClaude.identityMatches(executable: executable, identityFile: identityFile)
}
func wrapperMatches(_ environment: [String: String], topLevel: Bool) -> Bool? {
    guard topLevel, let targetFile = installedTargetFile,
          let configured = environment["CLAUDE_CODE_PROCESS_WRAPPER"], !configured.isEmpty else { return nil }
    let wrapper = URL(fileURLWithPath: targetFile).deletingLastPathComponent().appendingPathComponent("process-wrapper")
    guard FileManager.default.isExecutableFile(atPath: wrapper.path) else { return nil }
    guard configured.hasPrefix("/"), !configured.utf8.contains(0) else { return false }
    return URL(fileURLWithPath: configured).resolvingSymlinksInPath().path == wrapper.resolvingSymlinksInPath().path
}
func unmanagedClaude(_ executable: String, topLevel: Bool, journal: SessionJournal?) async -> Bool? {
    guard topLevel, let journal else { return nil }
    let records = await journal.all()
    return await Task.detached {
        ProcessInventory.hasUnmanaged(executable: executable, managed: records)
    }.value
}
func activeManagedSessionCount(_ journal: SessionJournal) async -> Int {
    let records = await journal.all().filter(\.isTopLevel)
    return await Task.detached {
        records.reduce(into: 0) { count, record in
            guard let identity = ProcessIdentity.read(record.pid),
                  record.matchesProcess(identity) else { return }
            count += 1
        }
    }.value
}
func monitor(pid: pid_t, start: ProcessIdentity, executable: String, environment: [String: String],
             customEndpointPresent: Bool, initialLocale: Data?, historyTracker: HistoryTracker?,
             journal: SessionJournal, sessionExitTracker: SessionExitTracker, topLevel: Bool,
             workingDirectory: String?, additionalSettingsPath: String?,
             commandLineSettings: SelectiveSettings.Findings?,
             commandLineRoutingEnvironment: [String: String],
             commandLineRoutingConflict: Bool,
             processAuthenticationContext: String?,
            authenticationContextTracker: AuthenticationContextTracker,
            claudeFailureTracker: ClaudeFailureTracker,
            fixtureAssessment: (@Sendable (Bool, Int) -> SafetyEvaluation)? = nil) async -> Bool {
    func originalExited() -> Bool {
        guard let current = ProcessIdentity.read(pid) else {
            return kill(pid, 0) == -1 && errno == ESRCH
        }
        return current.uid != start.uid || current.startSeconds != start.startSeconds ||
            current.startMicroseconds != start.startMicroseconds
    }
    // Give the authorized launcher time to replace itself with the target.
    try? await Task.sleep(for: .seconds(2))
    // A live process whose identity cannot be inspected must not silently
    // disappear from the journal.
    guard let identity = ProcessIdentity.read(pid) else { return originalExited() }
    guard identity.uid == start.uid, identity.startSeconds == start.startSeconds,
          identity.startMicroseconds == start.startMicroseconds else { return true }
    if identity.executable != executable {
        // The launcher did not become the approved executable in time (or
        // changed to a different one). Stop the same verified process rather
        // than dropping its record while it may still execute the command.
        let force = (try? GuardPolicy.load(path: policyPath))?.forceTerminate ?? false
        return await ManagedProcess.terminate(identity, force: force)
    }
    let settingsPaths = SelectiveSettings.paths(environment: environment, workingDirectory: workingDirectory,
                                                additionalSettingsPath: additionalSettingsPath)
    var supervisorStaleObserved = false
    while identity.stillMatches() {
        guard let policy = try? GuardPolicy.load(path: policyPath) else {
            return await ManagedProcess.terminate(identity, force: false)
        }
        let initialSettings = systemFingerprint.captureSettings(paths: settingsPaths)
        let initialEpoch = await networkEpoch.current()
        let initialFingerprint = systemFingerprint.capture()
        let currentLocale = systemFingerprint.captureLocale()
        let localeChanged: Bool? = {
            guard let initialLocale, let currentLocale else { return nil }
            return initialLocale != currentLocale
        }()
        let managedCount = await activeManagedSessionCount(journal)
        let recentStarts = await launchRateTracker?.count()
        let unmanaged = await unmanagedClaude(executable, topLevel: topLevel, journal: journal)
        let otherInstall = topLevel ? await Task.detached {
            ProcessInventory.hasOtherClaudeInstallation(excluding: executable)
        }.value : nil
        let failureCounts: ClaudeFailureCounts?
        if let digest = await state.failureSessionDigest(pid: pid, identity: identity) {
            failureCounts = try? await claudeFailureTracker.counts(for: digest)
        } else {
            failureCounts = nil
        }
        let result: SafetyEvaluation
        if let fixtureAssessment {
            result = fixtureAssessment(supervisorStaleObserved, policy.runtimeMinimumScore)
        } else {
            result = await assess(environment: environment, minimumScore: policy.runtimeMinimumScore,
                                  allowIPWho: policy.allowIPWho, allowProxyCheck: policy.allowProxyCheck,
                                  enableUDPCheck: policy.enableUDPCheck,
                                  stunEndpoint: policy.stunEndpoint, customEndpointPresent: customEndpointPresent,
                                  historyTracker: historyTracker, trustedEndpoints: policy.trustedEndpoints,
                                  managedSessionCount: managedCount,
                                  recentManagedStarts: recentStarts, networkEpoch: initialEpoch,
                                  networkFingerprint: initialFingerprint, sessionLocaleChanged: localeChanged,
                                  sessionExitTracker: sessionExitTracker,
                                  installedExecutableMatches: installedTargetMatches(executable, topLevel: topLevel),
                                  officialWrapperMatches: wrapperMatches(environment, topLevel: topLevel),
                                  unmanagedClaudeObserved: unmanaged,
                                  otherClaudeInstallationObserved: otherInstall,
                                  trackAuthenticationContext: topLevel,
                                  processAuthenticationContext: processAuthenticationContext,
                                  authenticationContextTracker: authenticationContextTracker,
                                  workingDirectory: workingDirectory,
                                  additionalSettingsPath: additionalSettingsPath,
                                  commandLineSettings: commandLineSettings,
                                  commandLineRoutingEnvironment: commandLineRoutingEnvironment,
                                  commandLineRoutingConflict: commandLineRoutingConflict,
                                  supervisorStaleObserved: supervisorStaleObserved,
                                  dnsPathEvidence: await state.dnsEvidence(pid),
                                  dnsRequiredProtocol: policy.dnsRequiredProtocol,
                                  dnsEncryptionDowngradeObserved: await state.dnsEncryptionDowngradeObserved(pid),
                                  claudeFailureCounts: failureCounts)
        }
        guard identity.stillMatches() else { return originalExited() }
        let currentEpoch = await networkEpoch.current()
        if initialSettings == nil || systemFingerprint.captureSettings(paths: settingsPaths) != initialSettings ||
            initialFingerprint == nil || systemFingerprint.capture() != initialFingerprint ||
            currentEpoch != initialEpoch || (result.decision != .allow && result.decision != .warning) {
            await state.setSession(pid, response: GuardResponse(decision: "hold", scoreUpperBound: result.scoreUpperBound,
                unknownCount: result.unknownRuleIDs.count + result.missingRuleIDs.count,
                unknownRules: (result.unknownRuleIDs + result.missingRuleIDs).sorted(),
                reason: localeChanged == true ? "受管会话期间系统时区、语言或区域已变化，正在结束会话。" :
                    "受管会话的环境未通过检查，正在结束会话。",
                findings: visibleFindings(result), ruleStatuses: visibleRuleStatuses(result),
                assessmentContext: .managedSession))
            return await ManagedProcess.terminate(identity, force: policy.forceTerminate)
        }
        await state.setSession(pid, response: GuardResponse(decision: result.decision.rawValue,
            safetyScore: result.safetyScore, scoreUpperBound: result.scoreUpperBound,
            unknownCount: result.unknownRuleIDs.count + result.missingRuleIDs.count,
            unknownRules: (result.unknownRuleIDs + result.missingRuleIDs).sorted(),
            reason: "受管会话环境检查已完成。", findings: visibleFindings(result),
            ruleStatuses: visibleRuleStatuses(result), assessmentContext: .managedSession))
        let postPublishEpoch = await networkEpoch.current()
        let postPublishSettings = systemFingerprint.captureSettings(paths: settingsPaths)
        let postPublishFingerprint = systemFingerprint.capture()
        let postPublishPolicy = try? GuardPolicy.load(path: policyPath)
        let settingsChanged = initialSettings == nil || postPublishSettings != initialSettings
        let networkChanged = initialFingerprint == nil || postPublishEpoch != initialEpoch ||
            postPublishFingerprint != initialFingerprint
        let policyChanged = postPublishPolicy != policy
        if settingsChanged || networkChanged || policyChanged {
            if settingsChanged || networkChanged ||
                !(postPublishPolicy?.hasSameRuntimeAssessment(as: policy) ?? false) {
                supervisorStaleObserved = true
            }
            await state.invalidate()
            continue
        }
        let epoch = initialEpoch
        for tick in 0..<30 {
            try? await Task.sleep(for: .seconds(1))
            if systemFingerprint.captureSettings(paths: settingsPaths) != initialSettings {
                await state.invalidate()
                supervisorStaleObserved = true
                break
            }
            if await networkEpoch.current() != epoch {
                supervisorStaleObserved = true
                break
            }
            if (try? GuardPolicy.load(path: policyPath)) != policy { break }
            if !identity.stillMatches() { return originalExited() }
            if tick % 5 == 4 {
                guard let fingerprint = systemFingerprint.capture() else {
                    supervisorStaleObserved = true
                    break
                }
                let changed = await CurrentAssessment.sessionExitChanged(environment: environment,
                    tracker: sessionExitTracker, networkEpoch: epoch, networkFingerprint: fingerprint)
                if changed != false {
                    supervisorStaleObserved = true
                    break
                }
            }
        }
        let currentPolicy = try? GuardPolicy.load(path: policyPath)
        let runtimeAssessmentChanged = currentPolicy.map {
            !$0.hasSameRuntimeAssessment(as: policy)
        } ?? true
        if await networkEpoch.current() != epoch || runtimeAssessmentChanged {
            supervisorStaleObserved = true
        }
    }
    return originalExited()
}

func managedAncestor(of child: ProcessIdentity, journal: SessionJournal) async -> ProcessIdentity? {
    ManagedProcess.ancestor(of: child, records: await journal.all())
}
func stopManagedAncestor(_ identity: ProcessIdentity, force: Bool) async {
    if !(await ManagedProcess.terminate(identity, force: force)) {
        await state.fail("无法结束一个受管会话，请手动检查。")
    }
}
func fixtureRegisterSession(_ request: GuardRequest, journal: SessionJournal?) async throws -> GuardResponse? {
    #if DEBUG
    if request.action == "fixture-record-launch-rate" {
        guard let launchRateTracker else {
            return GuardResponse(decision: "hold", reason: "启动频率存储不可用。")
        }
        do {
            _ = try await launchRateTracker.recordStart()
            return GuardResponse(decision: "allow", reason: "启动频率状态已写入。")
        } catch {
            return GuardResponse(decision: "hold",
                reason: "无法安全保存启动频率状态，已阻止 Claude 启动。")
        }
    }
    if request.action == "fixture-record-session",
       let journal, let identity = ProcessIdentity.read(getpid(), ownedBy: getuid()) {
        let record = SessionRecord(identity: identity, executable: identity.executable)
        do {
            try await journal.add(record)
            return GuardResponse(decision: "allow", reason: "受管会话状态已写入。")
        } catch {
            return GuardResponse(decision: "hold", reason: "无法安全保存受管会话状态。")
        }
    }
    if request.action == "fixture-advance-network-epoch" {
        await networkEpoch.advance()
        return GuardResponse(decision: "allow",
            reason: "测试夹具已推进本地网络代次。")
    }
    if request.action == "fixture-post-wake" {
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.didWakeNotification,
                                                    object: NSWorkspace.shared)
        return GuardResponse(decision: "allow",
            reason: "测试夹具已触发本地唤醒通知。")
    }
    if request.action == "fixture-monitor-generation",
       let pid = request.sessionPID, let seconds = request.sessionStartSeconds,
       let micros = request.sessionStartMicroseconds, let environment = request.environment,
       environment.keys.allSatisfy({ CurrentAssessment.environmentKeys.contains($0) }),
       let journal, let identity = ProcessIdentity.read(pid, ownedBy: getuid()),
       identity.startSeconds == seconds, identity.startMicroseconds == micros,
       let executable = request.executable, executable == identity.executable {
        let record = SessionRecord(identity: identity, executable: executable, isTopLevel: true)
        try await journal.add(record)
        let generationAssessment: @Sendable (Bool, Int) -> SafetyEvaluation = { stale, threshold in
            SafetyEvaluator.evaluate(SafetyRuleCatalog.ids.map { rule in
                let status: ObservationStatus
                if rule == "F04" {
                    status = stale ? .triggered(.standard, deduplicationKey: nil) : .passed
                } else {
                    status = .notApplicable
                }
                return RuleObservation(id: rule, status: status)
            }, minimumScore: threshold)
        }
        let sessionTracker = SessionExitTracker()
        let terminated = await monitor(pid: pid, start: identity, executable: executable,
            environment: environment, customEndpointPresent: false,
            initialLocale: systemFingerprint.captureLocale(), historyTracker: historyTracker,
            journal: journal, sessionExitTracker: sessionTracker, topLevel: false,
            workingDirectory: request.workingDirectory, additionalSettingsPath: nil,
            commandLineSettings: nil, commandLineRoutingEnvironment: [:],
            commandLineRoutingConflict: false, processAuthenticationContext: nil,
            authenticationContextTracker: authenticationContextTracker,
            claudeFailureTracker: claudeFailureTracker,
            fixtureAssessment: generationAssessment)
        await state.removeSession(pid)
        if terminated {
            try? await journal.remove(record)
            return GuardResponse(decision: "allow",
                reason: "F04 generation fixture observed the policy change and stopped the session.")
        }
        return GuardResponse(decision: "deny", reason: "F04 generation fixture did not stop the session.")
    }
    if request.action == "fixture-dns-downgrade" {
        let probePID = getpid()
        guard let identity = ProcessIdentity.read(probePID, ownedBy: getuid()), let journal else {
            return GuardResponse(decision: "deny", reason: "无法获取 DNS 测试进程身份。")
        }
        let record = SessionRecord(identity: identity, executable: identity.executable)
        try await journal.add(record)
        func evidence(_ security: DNSPathEvidence.ResolverSecurity) -> DNSPathEvidence {
            DNSPathEvidence(pid: probePID, pidVersion: 1,
                processStartSeconds: identity.startSeconds,
                processStartMicroseconds: identity.startMicroseconds,
                domainClass: .anthropicAPI, transport: .udp,
                resolverIdentity: "fixture-resolver", resolverSecurity: security)
        }
        let encrypted = evidence(.dnsOverHTTPS)
        let cleartext = evidence(.cleartext)
        let baselineRecorded = try await journal.observeDNSProtection(encrypted) == false
        await state.recordDNS(encrypted)
        let downgrade = try await journal.observeDNSProtection(cleartext) == true
        await state.recordDNS(cleartext, downgradeObserved: downgrade)
        let downgradeDetected = await state.dnsEncryptionDowngradeObserved(probePID)
        await state.removeSession(probePID)
        try await journal.remove(record)
        return GuardResponse(decision: baselineRecorded && downgradeDetected ? "allow" : "deny",
            reason: baselineRecorded && downgradeDetected
                ? "会话内 DNS 加密降级已识别并登记。" : "DNS 加密降级状态机未通过。")
    }
    if request.action == "fixture-wake-observer" {
        let probePID = getpid()
        if let identity = ProcessIdentity.read(probePID, ownedBy: getuid()) {
            await state.recordDNS(DNSPathEvidence(pid: probePID, pidVersion: 1,
                processStartSeconds: identity.startSeconds,
                processStartMicroseconds: identity.startMicroseconds,
                domainClass: .anthropicAPI, transport: .udp,
                resolverIdentity: "fixture-resolver"))
        }
        await state.setSession(probePID, response: GuardResponse(decision: "allow", safetyScore: 100,
                                                                 reason: "wake observer fixture"))
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.didWakeNotification,
                                                    object: NSWorkspace.shared)
        var invalidated = false
        for _ in 0..<100 {
            if await state.sessionStatusSnapshot()[probePID]?.decision == "hold",
               await state.dnsEvidence(probePID) == nil {
                invalidated = true
                break
            }
            try? await Task.sleep(for: .milliseconds(10))
        }
        await state.removeSession(probePID)
        return GuardResponse(decision: invalidated ? "allow" : "deny",
                             reason: invalidated ? "唤醒通知已使旧会话状态与 DNS 观测失效。" :
                                "唤醒通知没有触发完整状态复核。")
    }
    if request.action == "fixture-reset-session-state", let journal {
        for record in await journal.all() {
            try? await journal.remove(record)
            await state.removeSession(record.pid)
        }
        await state.set(GuardResponse(decision: "hold", reason: "夹具会话状态已重置。"))
        return GuardResponse(decision: "allow", reason: "夹具会话状态已重置。")
    }
    guard request.action == "fixture-register-session",
          let pid = request.sessionPID, let seconds = request.sessionStartSeconds,
          let micros = request.sessionStartMicroseconds, let journal,
          let identity = ProcessIdentity.read(pid, ownedBy: getuid()),
          identity.startSeconds == seconds, identity.startMicroseconds == micros else { return nil }
    let record = SessionRecord(identity: identity, executable: identity.executable, isTopLevel: true)
    try await journal.add(record)
    return GuardResponse(decision: "allow", reason: "测试夹具会话已登记。",
                         managedSessions: await journal.all().count)
    #else
    return nil
    #endif
}

let server: Int32
do { server = try GuardIPC.listen(path: socketPath) }
catch {
    FileHandle.standardError.write(Data("safe-claude-agent: 无法启动本地服务：\(error)\n".utf8))
    exit(1)
}
let journal = try? SessionJournal(path: journalPath)
let dnsEvidenceSpool = DNSPathEvidenceSpool.shared()
let historyPath = URL(fileURLWithPath: socketPath).deletingLastPathComponent().appendingPathComponent("history.json").path
let historyTracker: HistoryTracker? = {
    // Isolated custom sockets are frequently used for tests and never touch
    // the user's Keychain.
    guard socketPath == GuardIPC.socketPath, let historyKeyData else { return nil }
    return try? HistoryTracker(persistentPath: historyPath, keyData: historyKeyData)
}()

Task.detached {
    var previous = systemFingerprint.capture()
    while !Task.isCancelled {
        try? await Task.sleep(for: .seconds(2))
        await routeChanges.observe(systemFingerprint.captureRouteConfiguration())
        let current = systemFingerprint.capture()
        if current != previous {
            await networkEpoch.advance()
            await state.invalidate()
            previous = current
        }
    }
}

// Consume only short-lived DNS observations that match a currently journaled
// process birth identity. These observations enrich path evidence; by
// themselves they never turn any DNS rule into a pass.
Task.detached {
    guard let dnsEvidenceSpool, let journal else { return }
    while !Task.isCancelled {
        do {
            let observations = try dnsEvidenceSpool.drain()
            let records = await journal.all()
            for event in observations {
                guard let record = records.first(where: { $0.pid == event.pid }),
                   let current = ProcessIdentity.read(event.pid, ownedBy: getuid()),
                   event.matches(current, session: record) else { continue }
                guard let downgrade = try await journal.observeDNSProtection(event) else { continue }
                await state.recordDNS(event, downgradeObserved: downgrade)
            }
        } catch {
            // Missing/corrupt shared evidence cannot become a clean DNS result.
            // D01 needs a fresh request-bound path observation; missing D04
            // policy evidence remains critical unknown.
        }
        try? await Task.sleep(for: .milliseconds(500))
    }
}

// Processes launched through an absolute path can bypass PATH integration.
// Recognize only the exact installed Claude executable and signal only a
// freshly verified same-user identity that is absent from the journal.
Task.detached {
    guard let journal, let installedTargetFile else { return }
    while !Task.isCancelled {
        if await state.canMonitorUnmanaged(),
           let executable = InstalledClaude.selectedExecutable(targetFile: installedTargetFile) {
            let records = await journal.all()
            let identities = await Task.detached {
                ProcessInventory.unmanaged(executable: executable, managed: records)
            }.value
            if let identities, !identities.isEmpty,
               InstalledClaude.selectedExecutable(targetFile: installedTargetFile) == executable {
                let current = await journal.all()
                let unregistered = identities.filter { identity in
                    identity.stillMatches() && !current.contains(where: { $0.matchesProcess(identity) })
                }
                if !unregistered.isEmpty, await state.beginUnmanagedStop() {
                    let force = (try? GuardPolicy.load(path: policyPath))?.forceTerminate ?? false
                    await withTaskGroup(of: Bool.self) { group in
                        for identity in unregistered {
                            group.addTask { await ManagedProcess.terminate(identity, force: force) }
                        }
                        for await stopped in group where !stopped {
                            await state.fail("无法结束一个未受管 Claude 进程，请手动检查。")
                        }
                    }
                    await state.endUnmanagedStop()
                }
            }
        }
        try? await Task.sleep(for: .seconds(2))
    }
}

Task.detached {
    guard let journal else { await state.fail("无法读取受管会话记录。"); return }
    let previous = await journal.all()
    // A launcher may have been interrupted between authorization and exec.
    // Such a launcher is durably journaled before receiving its ticket, so
    // an empty journal has nothing that needs the crash-recovery grace period.
    if !previous.isEmpty {
        try? await Task.sleep(for: .seconds(2))
    }
    for record in previous {
        if let identity = ProcessIdentity.read(record.pid), record.matchesProcess(identity) {
            let force = (try? GuardPolicy.load(path: policyPath))?.forceTerminate ?? false
            if !(await ManagedProcess.terminate(identity, force: force)) {
                await state.fail("恢复保护时无法结束一个受管会话。")
                continue
            }
        } else if ProcessIdentity.read(record.pid) == nil,
                  !(kill(record.pid, 0) == -1 && errno == ESRCH) {
            await state.fail("恢复保护时无法确认一个受管会话的身份。")
            continue
        }
        do { try await journal.remove(record) }
        catch { await state.fail("无法更新受管会话记录。") }
    }
    await state.finishRecovery()
    await networkEpoch.advance()
}

Task.detached {
    let env = CurrentAssessment.captureEnvironment()
    while !Task.isCancelled {
        let initialEpoch = await networkEpoch.current()
        let initialFingerprint = systemFingerprint.capture()
        let sampledPolicy = try? GuardPolicy.load(path: policyPath)
        if let policy = sampledPolicy {
            let result = await assess(environment: env, minimumScore: policy.minimumScore,
                                      allowIPWho: policy.allowIPWho, allowProxyCheck: policy.allowProxyCheck,
                                      enableUDPCheck: policy.enableUDPCheck,
                                      stunEndpoint: policy.stunEndpoint, historyTracker: historyTracker,
                                      trustedEndpoints: policy.trustedEndpoints,
                                      networkEpoch: initialEpoch, networkFingerprint: initialFingerprint,
                                      dnsRequiredProtocol: policy.dnsRequiredProtocol)
            if initialFingerprint != nil, systemFingerprint.capture() == initialFingerprint,
               await networkEpoch.current() == initialEpoch {
                await state.set(GuardResponse(decision: result.decision.rawValue, safetyScore: result.safetyScore,
                    scoreUpperBound: result.scoreUpperBound, unknownCount: result.unknownRuleIDs.count + result.missingRuleIDs.count,
                    unknownRules: (result.unknownRuleIDs + result.missingRuleIDs).sorted(),
                    reason: result.decision == .hold ? "默认环境有检查尚未完成，暂不允许启动。" : "默认环境检查已完成。",
                    findings: visibleFindings(result), ruleStatuses: visibleRuleStatuses(result),
                    assessmentContext: .agentDefault))
            } else {
                await state.set(GuardResponse(decision: "hold", reason: "网络已变化，正在重新检查。"))
            }
        } else {
            await state.set(GuardResponse(decision: "hold", reason: "防护设置无法读取，请检查设置文件。"))
        }
        let epoch = initialEpoch
        for _ in 0..<300 {
            try? await Task.sleep(for: .seconds(1))
            if await networkEpoch.current() != epoch { break }
            if (try? GuardPolicy.load(path: policyPath)) != sampledPolicy { break }
        }
    }
}

while true {
    let fd = accept(server, nil, nil)
    if fd < 0 { if errno == EINTR { continue }; break }
    Task.detached {
        defer { close(fd) }
        guard await state.acquireRequest() else { return }
        do {
            try GuardIPC.configureClient(fd)
            let request = try GuardIPC.receive(GuardRequest.self, fd: fd)
            guard request.version == 1 else { throw GuardIPCError.invalidMessage }
            var response: GuardResponse
            if let fixtureResponse = try await fixtureRegisterSession(request, journal: journal) {
                response = fixtureResponse
            } else if request.action == "claude-failure-event",
                      let digest = request.failureSessionDigest,
                      let rawKind = request.failureKind,
                      let kind = ClaudeFailureEvent.Kind(rawValue: rawKind),
                      let journal,
                      let peer = ProcessIdentity.read(try GuardIPC.peerPID(fd), ownedBy: getuid()),
                      let ancestor = await managedAncestor(of: peer, journal: journal),
                      let record = await journal.all().first(where: { $0.matchesProcess(ancestor) }) {
                let activePolicy = try? GuardPolicy.load(path: policyPath)
                let force = activePolicy?.forceTerminate ?? false
                do {
                    let counts = try await claudeFailureTracker.record(
                        sessionDigest: digest, kind: kind)
                    await state.recordFailureEvidence(pid: record.pid, identity: ancestor, sessionDigest: digest)
                    var exceeded: [(String, Int)] = []
                    if counts.apiFailuresInMinute > 10 { exceeded.append(("G03", 10)) }
                    if counts.authenticationFailuresInTenMinutes >= 3 { exceeded.append(("G04", 15)) }
                    if !exceeded.isEmpty {
                        let oldStatus = await state.sessionStatusSnapshot()[record.pid]
                        let oldTriggered = Set(oldStatus?.ruleStatuses?.filter { $0.status == "triggered" }
                            .map(\.rule) ?? [])
                        let newRules = exceeded.filter { !oldTriggered.contains($0.0) }
                        let violations = newRules
                        let deduction = violations.reduce(0) { $0 + $1.1 }
                        let statuses = (oldStatus?.ruleStatuses ?? []) +
                            violations.map { RuleReportStatus(rule: $0.0, status: "triggered", points: $0.1) }
                        let findings = (oldStatus?.findings ?? []) +
                            violations.map { GuardFinding(rule: $0.0, points: $0.1) }
                        let updatedScore = oldStatus?.safetyScore.map { max(0, $0 - deduction) }
                        let minimumScore = activePolicy?.runtimeMinimumScore
                        // An event threshold makes the signal actionable; the
                        // configured runtime score decides whether the session
                        // must be stopped. A missing baseline cannot be treated
                        // as a safe score.
                        let shouldTerminate = ClaudeFailureDisposition.shouldTerminate(
                            safetyScore: updatedScore, minimumScore: minimumScore)
                        let violationResponse = GuardResponse(
                            decision: shouldTerminate ? "deny" : "allow", safetyScore: updatedScore,
                            scoreUpperBound: max(0, (oldStatus?.scoreUpperBound ?? 100) - deduction),
                            reason: shouldTerminate
                                ? "受管会话扣分后低于运行阈值，正在执行保护策略。"
                                : "已记录受管会话失败风险；当前评分仍达到运行阈值。",
                            findings: findings, ruleStatuses: statuses,
                            assessmentContext: .managedSession)
                        await state.set(violationResponse)
                        await state.setSession(record.pid, response: violationResponse)
                        if shouldTerminate {
                            Task.detached {
                                let terminated = await ManagedProcess.terminate(ancestor, force: force)
                                if terminated {
                                    try? await journal.remove(record)
                                    await state.removeSession(record.pid)
                                } else {
                                    await state.fail("失败事件触发保护，但受管会话未能结束，请立即手动检查。")
                                }
                            }
                        }
                        response = GuardResponse(decision: "allow",
                            reason: shouldTerminate
                                ? "失败事件已记录，评分低于运行阈值，Agent 正在结束受管会话。"
                                : "失败事件已记录；当前评分仍达到运行阈值，会话继续运行。")
                    } else {
                        response = GuardResponse(decision: "allow", reason: "受管失败事件已记录。")
                    }
                } catch {
                    await state.fail("受管失败事件无法安全记录，正在结束 Claude 会话。")
                    await state.setSession(record.pid, response: GuardResponse(
                        decision: "deny", reason: "受管失败事件无法安全记录，正在结束 Claude 会话。",
                        assessmentContext: .managedSession))
                    Task.detached {
                        let terminated = await ManagedProcess.terminate(ancestor, force: force)
                        if terminated {
                            try? await journal.remove(record)
                            await state.removeSession(record.pid)
                        }
                    }
                    response = GuardResponse(decision: "hold",
                        reason: "失败事件无法安全记录，Agent 正在结束受管会话。")
                }
            } else if request.action == "sessions" {
                guard let journal else { throw GuardIPCError.unavailable }
                let records = await journal.all()
                let statuses = await state.sessionStatusSnapshot()
                let summaries = records.compactMap { record -> GuardSessionSummary? in
                    guard let identity = ProcessIdentity.read(record.pid, ownedBy: getuid()),
                          record.matchesProcess(identity) else { return nil }
                    let session = statuses[record.pid]
                    return GuardSessionSummary(pid: record.pid, startSeconds: record.startSeconds,
                        startMicroseconds: record.startMicroseconds, isTopLevel: record.isTopLevel,
                        decision: session?.decision ?? "checking", safetyScore: session?.safetyScore,
                        checkedAt: session?.checkedAt)
                }
                response = GuardResponse(decision: "allow", reason: "受管会话状态。",
                                         managedSessions: summaries.count, sessions: summaries)
            } else if request.action == "terminate-session",
                      let pid = request.sessionPID, let seconds = request.sessionStartSeconds,
                      let micros = request.sessionStartMicroseconds, let journal,
                      let record = await journal.all().first(where: {
                          $0.pid == pid && $0.startSeconds == seconds && $0.startMicroseconds == micros
                      }),
                      let policy = try? GuardPolicy.load(path: policyPath),
                      let identity = ProcessIdentity.read(pid, ownedBy: getuid()), record.matches(identity) {
                let terminated = await ManagedProcess.terminate(identity, force: policy.forceTerminate)
                if terminated { try? await journal.remove(record) }
                response = GuardResponse(decision: terminated ? "allow" : "hold",
                    reason: terminated ? "受管会话已结束。" :
                        (policy.forceTerminate ? "会话未能结束，进程身份已重新核对。" : "会话未响应退出请求；强制结束策略当前关闭。"),
                    managedSessions: await journal.all().count)
            } else if request.action == "status" {
                let status = await state.get()
                response = GuardResponse(decision: status.decision, safetyScore: status.safetyScore,
                    scoreUpperBound: status.scoreUpperBound, unknownCount: status.unknownCount,
                    unknownRules: status.unknownRules,
                    reason: status.reason, findings: status.findings, ruleStatuses: status.ruleStatuses,
                    assessmentContext: status.assessmentContext,
                    checkedAt: status.checkedAt,
                    managedSessions: await journal?.all().count)
            } else if request.action == "prepare-uninstall" {
                let pending = await state.beginDrain()
                if let journal {
                    let count = await journal.all().count + pending
                    response = GuardResponse(decision: count == 0 ? "allow" : "hold",
                        reason: count == 0 ? "可以卸载。" : "仍有受管会话或启动检查。",
                        managedSessions: count)
                } else {
                    response = GuardResponse(decision: "hold", reason: "无法确认受管会话。")
                }
            } else if request.action == "cancel-uninstall" {
                await state.cancelDrain()
                await networkEpoch.advance()
                await state.invalidate()
                response = GuardResponse(decision: "hold", reason: "已取消卸载。")
            } else if request.action == "clear-history", let historyTracker {
                try await historyTracker.clear()
                await networkEpoch.advance()
                await state.invalidate()
                response = GuardResponse(decision: "hold", reason: "历史已清除，正在重新检查。")
            } else if request.action == "validate", let token = request.ticket,
                      let identity = ProcessIdentity.read(try GuardIPC.peerPID(fd)), identity.uid == getuid(),
                      let fingerprint = systemFingerprint.capture(),
                      let policy = try? GuardPolicy.load(path: policyPath), await state.isHealthy(),
                      let accepted = await tickets.consume(token, identity: identity,
                                                           epoch: await networkEpoch.current(), fingerprint: fingerprint, policy: policy) {
                response = accepted.0
                if accepted.1 {
                    if let launchRateTracker, (try? await launchRateTracker.recordStart()) != nil {
                        response = accepted.0
                    } else {
                        response = GuardResponse(decision: "hold",
                            reason: "无法安全保存启动频率状态，已阻止 Claude 启动。")
                    }
                } else {
                    response = accepted.0
                }
            } else if request.action == "preflight", let environment = request.environment,
                      let executable = request.executable, executable.hasPrefix("/"),
                      let customEndpointPresent = request.customEndpointPresent,
                      let entryKind = request.entryKind, ["top", "child"].contains(entryKind),
                      request.workingDirectory.map({ $0.hasPrefix("/") && $0.utf8.count <= 4096 && !$0.utf8.contains(0) }) ?? true,
                      request.additionalSettingsPath.map({
                          $0.hasPrefix("/") && $0.utf8.count <= 4096 && !$0.utf8.contains(0)
                      }) ?? true,
                      validSettingsFindings(request.commandLineSettings),
                      (request.commandLineRoutingEnvironment?.count ?? 0) <= SelectiveSettings.proxyRoutingKeys.count,
                      request.commandLineRoutingEnvironment?.keys.allSatisfy(SelectiveSettings.proxyRoutingKeys.contains) ?? true,
                      request.commandLineRoutingEnvironment?.values.allSatisfy({
                          $0.utf8.count <= 8192 && !$0.utf8.contains(0)
                      }) ?? true,
                      !(request.commandLineRoutingConflict ?? false) || request.commandLineRoutingEnvironment != nil,
                      request.authenticationContext.map(AuthenticationContext.isValid) ?? true,
                      environment.keys.allSatisfy({ CurrentAssessment.environmentKeys.contains($0) }),
                      let identity = ProcessIdentity.read(try GuardIPC.peerPID(fd)), identity.uid == getuid(),
                      let policy = try? GuardPolicy.load(path: policyPath) {
                let settingsPaths = SelectiveSettings.paths(environment: environment,
                    workingDirectory: request.workingDirectory, additionalSettingsPath: request.additionalSettingsPath)
                let initialSettings = systemFingerprint.captureSettings(paths: settingsPaths)
                let initialEpoch = await networkEpoch.current()
                let initialFingerprint = systemFingerprint.capture()
                let initialLocale = systemFingerprint.captureLocale()
                let sessionExitTracker = SessionExitTracker()
                let started = ProcessInfo.processInfo.systemUptime
                let topLevel = entryKind == "top"
                guard let pendingCount = await state.reserve(identity.pid, topLevel: topLevel) else {
                    response = GuardResponse(decision: "hold", reason: "后台服务未就绪或启动检查正在进行。")
                    try GuardIPC.send(response, fd: fd)
                    await state.finishRequest()
                    return
                }
                let managedCount: Int?
                if let journal { managedCount = await activeManagedSessionCount(journal) }
                else { managedCount = nil }
                let recentStarts = await launchRateTracker?.count()
                let unmanaged = await unmanagedClaude(executable, topLevel: topLevel, journal: journal)
                let otherInstall = topLevel ? await Task.detached {
                    ProcessInventory.hasOtherClaudeInstallation(excluding: executable)
                }.value : nil
                let result = await assess(environment: environment, minimumScore: policy.minimumScore,
                                          allowIPWho: policy.allowIPWho, allowProxyCheck: policy.allowProxyCheck,
                                          enableUDPCheck: policy.enableUDPCheck,
                                          stunEndpoint: policy.stunEndpoint, customEndpointPresent: customEndpointPresent,
                                          historyTracker: historyTracker, trustedEndpoints: policy.trustedEndpoints,
                                          managedSessionCount: managedCount.map { $0 + pendingCount },
                                          recentManagedStarts: recentStarts.map { $0 + (topLevel ? 1 : 0) }, networkEpoch: initialEpoch,
                                          networkFingerprint: initialFingerprint,
                                          sessionLocaleChanged: initialLocale == nil ? nil : false,
                                          sessionExitTracker: sessionExitTracker,
                                          installedExecutableMatches: installedTargetMatches(executable, topLevel: topLevel),
                                          officialWrapperMatches: wrapperMatches(environment, topLevel: topLevel),
                                          unmanagedClaudeObserved: unmanaged,
                                          otherClaudeInstallationObserved: otherInstall,
                                          trackAuthenticationContext: topLevel,
                                          processAuthenticationContext: request.authenticationContext,
                                          authenticationContextTracker: authenticationContextTracker,
                                          workingDirectory: request.workingDirectory,
                                          additionalSettingsPath: request.additionalSettingsPath,
                                          commandLineSettings: request.commandLineSettings,
                                          commandLineRoutingEnvironment: request.commandLineRoutingEnvironment ?? [:],
                                          commandLineRoutingConflict: request.commandLineRoutingConflict ?? false,
                                          dnsRequiredProtocol: policy.dnsRequiredProtocol)
                let finalEpoch = await networkEpoch.current()
                let networkStable = initialFingerprint != nil && systemFingerprint.capture() == initialFingerprint &&
                    finalEpoch == initialEpoch
                let withinDeadline = ProcessInfo.processInfo.systemUptime - started < 2.4
                let healthy = await state.isHealthy()
                let settingsStable = initialSettings != nil && systemFingerprint.captureSettings(paths: settingsPaths) == initialSettings
                let stable = networkStable && settingsStable && withinDeadline && healthy
                response = GuardResponse(decision: stable ? result.decision.rawValue : "hold",
                    safetyScore: stable ? result.safetyScore : nil, scoreUpperBound: result.scoreUpperBound,
                    unknownCount: result.unknownRuleIDs.count + result.missingRuleIDs.count,
                    unknownRules: (result.unknownRuleIDs + result.missingRuleIDs).sorted(),
                    reason: !healthy ? "后台服务正在恢复或存在未处理故障。" :
                        (!networkStable ? "网络在检查期间变化，请重试。" :
                        (!settingsStable ? "Claude 设置在检查期间变化或无法读取，请重试。" :
                        (!withinDeadline ? "环境检查超时，请重试。" :
                        (result.decision == .hold ? "有检查尚未完成，暂不允许启动。" : "启动环境检查已完成。")))),
                    findings: visibleFindings(result), ruleStatuses: visibleRuleStatuses(result),
                    assessmentContext: .claudeLaunch,
                    expiresAt: stable && (result.decision == .allow || result.decision == .warning)
                        ? Date().addingTimeInterval(1) : nil)
                await state.setLaunch(response)
                if stable && (result.decision == .allow || result.decision == .warning) {
                    let record = SessionRecord(identity: identity, executable: executable, isTopLevel: topLevel)
                    do {
                        guard let journal else { throw GuardIPCError.unavailable }
                        try await journal.add(record)
                        guard let initialFingerprint, let initialSettings,
                              let token = await tickets.issue(identity: identity, epoch: initialEpoch, fingerprint: initialFingerprint,
                                                               policy: policy, settingsPaths: settingsPaths, settingsFingerprint: initialSettings,
                                                               isTopLevel: topLevel, response: response) else {
                            do { try await journal.remove(record) }
                            catch { await state.fail("无法更新受管会话记录。") }
                            throw GuardIPCError.unavailable
                        }
                        response = GuardResponse(decision: response.decision, safetyScore: response.safetyScore,
                            scoreUpperBound: response.scoreUpperBound, unknownCount: response.unknownCount,
                            unknownRules: response.unknownRules,
                            reason: response.reason, findings: response.findings,
                            ruleStatuses: response.ruleStatuses, assessmentContext: response.assessmentContext,
                            checkedAt: response.checkedAt,
                            expiresAt: response.expiresAt, ticket: token)
                        Task.detached {
                            let completed = await monitor(pid: identity.pid, start: identity,
                                                          executable: executable, environment: environment,
                                                          customEndpointPresent: customEndpointPresent,
                                                          initialLocale: initialLocale,
                                                          historyTracker: historyTracker, journal: journal,
                                                          sessionExitTracker: sessionExitTracker, topLevel: topLevel,
                                                          workingDirectory: request.workingDirectory,
                                                          additionalSettingsPath: request.additionalSettingsPath,
                                                          commandLineSettings: request.commandLineSettings,
                                                          commandLineRoutingEnvironment: request.commandLineRoutingEnvironment ?? [:],
                                                          commandLineRoutingConflict: request.commandLineRoutingConflict ?? false,
                                                          processAuthenticationContext: request.authenticationContext,
                                                          authenticationContextTracker: authenticationContextTracker,
                                                          claudeFailureTracker: claudeFailureTracker)
                            await state.removeSession(identity.pid)
                            if completed {
                                do { try await journal.remove(record) }
                                catch { await state.fail("无法更新受管会话记录。") }
                            } else { await state.fail("无法结束一个受管会话，请手动检查。") }
                        }
                    } catch {
                        response = GuardResponse(decision: "hold", reason: "无法登记受保护会话。")
                        await state.setLaunch(response)
                    }
                }
                if response.decision != "allow" && response.decision != "warning", let journal,
                   let ancestor = await managedAncestor(of: identity, journal: journal) {
                    Task.detached { await stopManagedAncestor(ancestor, force: policy.forceTerminate) }
                }
                await state.release(identity.pid)
            } else { throw GuardIPCError.invalidMessage }
            try GuardIPC.send(response, fd: fd)
        } catch { }
        await state.finishRequest()
    }
}
close(server)
