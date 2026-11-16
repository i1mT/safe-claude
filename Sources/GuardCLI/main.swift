import Foundation
import Darwin
import GuardCore
import AppKit

// Phase 01 diagnostic entry points. Never serialize the input environment.
func networkEnvironment() -> [String: String] {
    let keys = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY",
                "no_proxy", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "CLAUDE_CODE_CERT_STORE",
                "CLAUDE_CODE_CLIENT_CERT", "CLAUDE_CODE_CLIENT_KEY", "NODE_TLS_REJECT_UNAUTHORIZED",
                "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_USE_SYSTEM_CA"]
    var values: [String: String] = [:]
    for key in keys {
        if let value = getenv(key) { values[key] = String(cString: value) }
    }
    return values
}

var args = CommandLine.arguments
var socketPath = GuardIPC.socketPath
if args.count > 3, args[1] == "--socket" {
    socketPath = args[2]
    args.removeSubrange(1...2)
}
if args.count == 2, args[1] == "hook-event" {
    var payload = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let count = read(STDIN_FILENO, &buffer, buffer.count)
        if count < 0 && errno == EINTR { continue }
        guard count >= 0, payload.count + count <= 65_536 else {
            fputs("safe-claude: hook 事件无效。\n", stderr); exit(0)
        }
        if count == 0 { break }
        payload.append(contentsOf: buffer.prefix(count))
    }
    guard let event = ClaudeFailureEvent.parse(payload),
          let fd = try? GuardIPC.connect(path: socketPath) else { exit(0) }
    defer { close(fd) }
    let request = GuardRequest(action: "claude-failure-event",
                               failureSessionDigest: event.sessionDigest,
                               failureKind: event.kind.rawValue)
    if (try? GuardIPC.send(request, fd: fd)) != nil {
        _ = try? GuardIPC.receive(GuardResponse.self, fd: fd)
    }
    exit(0)
}
if args.count >= 4, ["exec", "exec-child"].contains(args[1]), args[2] == "--" {
    guard let localPolicy = try? GuardPolicy.load() else {
        fputs("safe-claude: 本机防护策略无法读取，已阻止启动。\n", stderr); exit(75)
    }
    let executable = URL(fileURLWithPath: args[3]).resolvingSymlinksInPath().path
    guard args[3].hasPrefix("/"), FileManager.default.isExecutableFile(atPath: executable) else {
        fputs("safe-claude: 找不到可执行的目标命令。\n", stderr); exit(127)
    }
    var environment = CurrentAssessment.captureEnvironment()
    var commandLineSettings = SelectiveSettings.modelEnvironment(environment)
    if let nodeOptions = getenv("NODE_OPTIONS") {
        commandLineSettings.merge(SelectiveSettings.nodeOptionsFindings(String(cString: nodeOptions)))
    }
    var commandLineRoutingEnvironment: [String: String] = [:]
    var commandLineRoutingConflict = false
    environment.removeValue(forKey: "ANTHROPIC_MODEL")
    environment.removeValue(forKey: "ANTHROPIC_DEFAULT_MODEL")
    var additionalSettingsPath: String?
    var settingsArgumentSeen = false
    let claudeArguments = Array(args.dropFirst(4))
    var index = 0
    while index < claudeArguments.count {
        let argument = claudeArguments[index]
        let value: String?
        if argument == "--settings" {
            guard index + 1 < claudeArguments.count, !settingsArgumentSeen else {
                fputs("safe-claude: --settings 参数无法安全检查，已阻止启动。\n", stderr); exit(75)
            }
            settingsArgumentSeen = true
            value = claudeArguments[index + 1]
            index += 1
        } else if argument.hasPrefix("--settings=") {
            guard !settingsArgumentSeen else {
                fputs("safe-claude: 多个 --settings 参数无法安全合并，已阻止启动。\n", stderr); exit(75)
            }
            settingsArgumentSeen = true
            value = String(argument.dropFirst("--settings=".count))
        } else if argument == "--model" {
            guard index + 1 < claudeArguments.count else {
                commandLineSettings.invalidModelIdentifier = true
                index += 1
                continue
            }
            commandLineSettings.merge(SelectiveSettings.modelArgument(claudeArguments[index + 1]))
            index += 1
            value = nil
        } else if argument.hasPrefix("--model=") {
            commandLineSettings.merge(SelectiveSettings.modelArgument(
                String(argument.dropFirst("--model=".count))))
            value = nil
        } else {
            value = nil
        }
        if let value {
            if value.hasPrefix("{") {
                guard let parsed = SelectiveSettings.inspectJSONContext(
                    Data(value.utf8), trustedEndpoints: localPolicy.trustedEndpoints) else {
                    fputs("safe-claude: --settings JSON 无法安全解析，已阻止启动。\n", stderr); exit(75)
                }
                var findings = parsed.findings
                if findings.customAutoMemoryDirectory {
                    findings.autoMemoryIndexEmpty = parsed.autoMemoryIndexIsEmpty(environment: environment)
                }
                commandLineSettings.merge(findings)
                for (key, routeValue) in parsed.routingEnvironment {
                    if let previous = commandLineRoutingEnvironment[key], previous != routeValue {
                        commandLineRoutingConflict = true
                    } else {
                        commandLineRoutingEnvironment[key] = routeValue
                    }
                }
                commandLineRoutingConflict = commandLineRoutingConflict || parsed.routingConflict
            } else {
                let path = value.hasPrefix("/")
                    ? URL(fileURLWithPath: value).standardizedFileURL.path
                    : URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                        .appendingPathComponent(value).standardizedFileURL.path
                guard path.utf8.count <= 4096, !path.utf8.contains(0),
                      SelectiveSettings.inspectFileContext(path: path,
                        trustedEndpoints: localPolicy.trustedEndpoints) != nil else {
                    fputs("safe-claude: --settings 文件无法安全检查，已阻止启动。\n", stderr); exit(75)
                }
                additionalSettingsPath = path
            }
        }
        index += 1
    }
    do {
        let fd = try GuardIPC.connect(path: socketPath)
        defer { close(fd) }
        let endpoint: String?
        if let rawEndpoint = getenv("ANTHROPIC_BASE_URL") {
            endpoint = String(cString: rawEndpoint)
        } else {
            endpoint = nil
        }
        let envEndpointRisk = endpoint.map {
            !TrustedEndpoint.isTrusted($0, allowlist: localPolicy.trustedEndpoints)
        } ?? false
        let customEndpointPresent = envEndpointRisk || commandLineSettings.customEndpoint
        try GuardIPC.send(GuardRequest(action: "preflight", environment: environment, executable: executable,
                                       workingDirectory: FileManager.default.currentDirectoryPath,
                                       additionalSettingsPath: additionalSettingsPath,
                                       commandLineSettings: commandLineSettings,
                                       commandLineRoutingEnvironment: commandLineRoutingEnvironment,
                                       commandLineRoutingConflict: commandLineRoutingConflict,
                                       authenticationContext: AuthenticationContext.processMode(),
                                       customEndpointPresent: customEndpointPresent,
                                       entryKind: args[1] == "exec" ? "top" : "child"), fd: fd)
        let response = try GuardIPC.receive(GuardResponse.self, fd: fd)
        guard response.version == 1, (response.decision == "allow" || response.decision == "warning"),
              let score = response.safetyScore, (0...100).contains(score), response.unknownCount == 0,
              let expiresAt = response.expiresAt, expiresAt > Date(), expiresAt.timeIntervalSinceNow <= 1.1,
              let ticket = response.ticket else {
            fputs("safe-claude: 启动已阻止：\(response.reason)\n", stderr)
            exit(response.decision == "deny" ? 78 : 75)
        }
        let validationFD = try GuardIPC.connect(path: socketPath)
        defer { close(validationFD) }
        try GuardIPC.send(GuardRequest(action: "validate", ticket: ticket), fd: validationFD)
        let validated = try GuardIPC.receive(GuardResponse.self, fd: validationFD)
        guard validated.version == 1, validated.decision == response.decision,
              validated.safetyScore == score, validated.unknownCount == 0,
              let validatedExpiry = validated.expiresAt, validatedExpiry > Date(),
              validatedExpiry.timeIntervalSinceNow <= 1.1 else {
            fputs("safe-claude: 环境已变化，启动已阻止。\n", stderr); exit(75)
        }
        try ProcessExecution.replace(executable: executable, arguments: Array(args.dropFirst(4)))
    } catch {
        fputs("safe-claude: 后台服务不可用或启动失败，已阻止启动。\n", stderr)
        exit(75)
    }
}
#if DEBUG
let serviceActions = ["status", "prepare-uninstall", "cancel-uninstall",
                      "fixture-wake-observer", "fixture-dns-downgrade",
                      "fixture-reset-session-state"]
#else
let serviceActions = ["status", "prepare-uninstall", "cancel-uninstall"]
#endif
if args.count == 2, serviceActions.contains(args[1]) {
    do {
        let fd = try GuardIPC.connect(path: socketPath)
        defer { close(fd) }
        try GuardIPC.send(GuardRequest(action: args[1]), fd: fd)
        let result = try GuardIPC.receive(GuardResponse.self, fd: fd)
        FileHandle.standardOutput.write(try JSONEncoder().encode(result))
        FileHandle.standardOutput.write(Data("\n".utf8))
        exit(0)
    } catch {
        fputs("safe-claude: 后台服务不可用。\n", stderr); exit(75)
    }
}
if args.count == 2, args[1] == "doctor" {
    let runningExecutable = ProcessIdentity.read(getpid())?.executable ?? args[0]
    let executableURL = URL(fileURLWithPath: runningExecutable).standardizedFileURL
    let inferredPrefix: URL = executableURL.deletingLastPathComponent().lastPathComponent == "libexec"
        ? executableURL.deletingLastPathComponent().deletingLastPathComponent()
        : URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/SafeClaude/installation")
    let shim = inferredPrefix.appendingPathComponent("bin/claude").resolvingSymlinksInPath().path
    func validLifecycleResource(at url: URL) -> Bool {
        guard let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              !object.isEmpty else { return false }
        return true
    }
    let agentModelLifecycleResourceValid = validLifecycleResource(
        at: inferredPrefix.appendingPathComponent(
            "libexec/SafeClaude_GuardCore.bundle/claude-model-lifecycle.json"))
    let appModelLifecycleResourceValid = validLifecycleResource(
        at: inferredPrefix.appendingPathComponent(
            "SafeClaude.app/Contents/MacOS/SafeClaude_GuardCore.bundle/claude-model-lifecycle.json"))
    let modelLifecycleResourcesValid = agentModelLifecycleResourceValid && appModelLifecycleResourceValid
    let searchPath = getenv("PATH").map { String(cString: $0) } ?? ""
    let selected = searchPath.split(separator: ":", omittingEmptySubsequences: false)
        .map { $0.isEmpty ? "." : String($0) }
        .map { URL(fileURLWithPath: $0).appendingPathComponent("claude").path }
        .first { FileManager.default.isExecutableFile(atPath: $0) }
        .map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path }
    let online: Bool = {
        guard let fd = try? GuardIPC.connect(path: socketPath) else { return false }
        defer { close(fd) }
        do {
            try GuardIPC.send(GuardRequest(action: "status"), fd: fd)
            return try GuardIPC.receive(GuardResponse.self, fd: fd).version == 1
        } catch { return false }
    }()
    let report: [String: Any] = [
        "agentOnline": online, "shimInstalled": FileManager.default.isExecutableFile(atPath: shim),
        "shimSelectedByPATH": selected == shim,
        "agentModelLifecycleResourceValid": agentModelLifecycleResourceValid,
        "appModelLifecycleResourceValid": appModelLifecycleResourceValid,
        "modelLifecycleResourcesValid": modelLifecycleResourcesValid,
        "externalWrapperPresent": getenv("CLAUDE_CODE_PROCESS_WRAPPER") != nil,
        "scope": "current-process",
        "shellAliasesAndAutomationNotVerified": true,
    ]
    FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]))
    FileHandle.standardOutput.write(Data("\n".utf8))
    exit(online && selected == shim && modelLifecycleResourcesValid ? 0 : 75)
}
if args.count == 4, args[1] == "stop-ui", args[2] == "--" {
    guard args[3].hasPrefix("/") else { exit(64) }
    let expected = URL(fileURLWithPath: args[3]).resolvingSymlinksInPath().path
    let apps = NSRunningApplication.runningApplications(withBundleIdentifier: "local.safeclaude.app").filter {
        $0.executableURL?.resolvingSymlinksInPath().path == expected
    }
    for app in apps { _ = app.terminate() }
    let deadline = ProcessInfo.processInfo.systemUptime + 2
    while apps.contains(where: { !$0.isTerminated }) && ProcessInfo.processInfo.systemUptime < deadline {
        try? await Task.sleep(for: .milliseconds(50))
    }
    exit(apps.allSatisfy(\.isTerminated) ? 0 : 75)
}
if (args.count == 3 || args.count == 4), args[1] == "assess-current", args[2] == "--ipwho",
   args.count == 3 || args[3] == "--proxycheck" {
    let environment = networkEnvironment()
    let trace = TraceProbe.observe(.api, environment: environment)
    let traceObservedAt = Date()
    var reputation: IPReputation?
    var reputationObservedAt: Date?
    var proxyCheck: ProxyCheckObservation?
    var proxyCheckObservedAt: Date?
    if case .observed(let observation) = trace {
        let proxyCheckKey = getenv("SAFE_CLAUDE_PROXYCHECK_API_KEY").map { String(cString: $0) }
        let useProxyCheck = args.count == 4
        // Both independent lookups use the same observed API address.
        // Record each completion separately rather than timestamping an earlier
        // response when the other provider eventually returns.
        async let geo: (IPReputation?, Date?) = {
            let value = try? await IPWhoGeolocation.fetch(ip: observation.ip, routingEnvironment: environment)
            return (value, value == nil ? nil : Date())
        }()
        async let proxy: (ProxyCheckObservation?, Date?) = {
            guard useProxyCheck else { return (nil, nil) }
            let value = try? await ProxyCheckV3.fetch(ip: observation.ip, routingEnvironment: environment,
                                                       apiKey: proxyCheckKey)
            return (value, value == nil ? nil : Date())
        }()
        (reputation, reputationObservedAt) = await geo
        (proxyCheck, proxyCheckObservedAt) = await proxy
    }
    let snapshot = LocalEnvironmentSnapshot.capture(targetHost: ClaudeTraceTarget.api.rawValue)
    let languages = reputation?.countryCode.flatMap { CountryLanguageCatalog.languages(for: $0) }
    let rules = EnvironmentAssessment.observations(snapshot: snapshot, apiTrace: trace,
                                                    reputation: reputation, countryLanguages: languages,
                                                    firstRun: nil, proxyCheck: proxyCheck,
                                                    proxyCheckObservedAt: proxyCheckObservedAt,
                                                    traceObservedAt: traceObservedAt, reputationObservedAt: reputationObservedAt)
    let result = SafetyEvaluator.evaluate(rules)
    let output: [String: Any] = [
        "scope": "current-process-diagnostic", "decision": result.decision.rawValue,
        "safetyScore": result.safetyScore as Any? ?? NSNull(), "scoreUpperBound": result.scoreUpperBound,
        "unknownCount": result.unknownRuleIDs.count, "unsupportedCount": result.unsupportedRuleIDs.count,
        "deductions": result.deductions.map { ["rule": $0.ruleID, "points": $0.points] as [String: Any] },
        "geolocationAvailable": reputation != nil, "reputationAvailable": proxyCheck != nil,
    ]
    let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
    exit(result.decision == .hold ? 75 : (result.decision == .deny ? 78 : 0))
}
if args.count >= 4, args[1] == "fixture-exec", args[2] == "--" {
    do {
        try ProcessExecution.replace(executable: args[3], arguments: Array(args.dropFirst(4)))
    } catch {
        fputs("fixture-exec failed: \(error)\n", stderr)
        exit(126)
    }
}
if args.count == 3, args[1] == "trace-check" {
    guard let target = ClaudeTraceTarget(rawValue: args[2]) else {
        fputs("unknown trace target\n", stderr)
        exit(64)
    }
    let result = TraceProbe.observe(target, environment: networkEnvironment())
    let output: [String: Any]
    switch result {
    case .observed(let observation):
        output = ["target": observation.targetHost, "status": "observed",
                  "hasIP": true, "hasCountry": observation.countryCode != nil,
                  "scope": "environment-only diagnostic"]
    case .unknown(let reason):
        output = ["target": target.rawValue, "status": "unknown", "reason": reason,
                  "scope": "environment-only diagnostic"]
    }
    let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
    if case .unknown = result { exit(75) }
    exit(0)
}
guard args.count == 3, args[1] == "probe-config" else {
    fputs("usage: safe-claude exec -- <absolute-executable> [args...] | status | doctor | probe-config <target-host> | trace-check <official-host> | assess-current --ipwho [--proxycheck]\n", stderr)
    exit(64)
}

let environment = networkEnvironment()
let result = ProxyConfiguration.resolve(
    targetHost: args[2],
    environment: environment
)
var output: [String: Any]
switch result {
case .direct(let reason):
    output = ["decision": "direct", "reason": reason]
case .proxy(let proxy):
    output = [
        "decision": "proxy", "scheme": proxy.scheme, "host": proxy.host,
        "port": proxy.port, "credentialsPresent": proxy.hasCredentials,
        "sourceKey": proxy.sourceKey, "source": proxy.source,
    ]
case .unknown(let reason):
    output = ["decision": "unknown", "reason": reason]
}
output["conflictingKeys"] = ProxyConfiguration.conflictingKeys(environment: environment)
let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
FileHandle.standardOutput.write(data)
FileHandle.standardOutput.write(Data("\n".utf8))
if case .unknown = result { exit(75) }
