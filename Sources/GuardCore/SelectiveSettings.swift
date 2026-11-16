import Darwin
import Foundation
import CoreFoundation

/// Streaming JSON inspection for selected `env` keys. Values of unrelated
/// keys are skipped byte-by-byte and never assembled into a string or stored.
public enum SelectiveSettings {
    /// Selected facts plus proxy values needed for a request-equivalent probe.
    /// Routing values stay in memory and are never part of Findings/Codable.
    public struct Inspection: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        public let findings: Findings
        public let routingEnvironment: [String: String]
        public let routingConflict: Bool
        fileprivate let autoMemoryDirectoryPath: String?
        fileprivate init(findings: Findings, routingEnvironment: [String: String],
                         routingConflict: Bool, autoMemoryDirectoryPath: String? = nil) {
            self.findings = findings
            self.routingEnvironment = routingEnvironment
            self.routingConflict = routingConflict
            self.autoMemoryDirectoryPath = autoMemoryDirectoryPath
        }
        public func autoMemoryIndexIsEmpty(environment: [String: String]) -> Bool? {
            guard let autoMemoryDirectoryPath else { return nil }
            return SelectiveSettings.autoMemoryIndexCensus(path: autoMemoryDirectoryPath,
                                                           environment: environment)
        }
        public var description: String { "SelectiveSettings.Inspection(redacted)" }
        public var debugDescription: String { description }
    }

    public struct Findings: Codable, Sendable {
        public var routingOverride = false
        public var customEndpoint = false
        public var tlsDisabled = false
        public var tlsDowngradeAllowed = false
        public var invalidTLSOptions = false
        /// Certificate files are reduced to validity labels locally. Paths
        /// and certificate bytes are never retained in Findings or IPC.
        public var clientCertificatesConfigured = false
        public var clientCertificateStatuses: Set<ClientCertificateStatus> = []
        public var invalidClientCertificate = false
        /// Presence only. Certificate paths and values are never retained.
        public var customTrustConfiguration = false
        public var invalidTrustConfiguration = false
        /// Locale values are low sensitivity and are needed to compare the
        /// effective Claude environment with macOS. No other setting values
        /// are retained.
        public var locale: [String: String] = [:]
        public var invalidLocaleKeys: Set<String> = []
        /// Effective opt-out signal, captured without retaining the setting's
        /// surrounding JSON or any unrelated environment values.
        public var autoMemoryDisabled: Bool?
        public var conflictingAutoMemorySetting = false
        public var customAutoMemoryDirectory = false
        /// True only when a complete, safe metadata census found no regular
        /// memory index entries. Nil means the directory could not be proven.
        public var autoMemoryIndexEmpty: Bool?
        public var authenticationModes: Set<String> = []
        public var invalidAuthenticationMode = false
        /// Strict model labels only; arbitrary settings strings are discarded.
        public var modelIdentifiers: Set<String> = []
        public var invalidModelIdentifier = false
        public init() {}
        private enum CodingKeys: String, CodingKey {
            case routingOverride, customEndpoint, tlsDisabled, tlsDowngradeAllowed, invalidTLSOptions
            case clientCertificatesConfigured, clientCertificateStatuses, invalidClientCertificate
            case customTrustConfiguration, invalidTrustConfiguration
            case locale, invalidLocaleKeys
            case autoMemoryDisabled, conflictingAutoMemorySetting, customAutoMemoryDirectory, autoMemoryIndexEmpty
            case authenticationModes, invalidAuthenticationMode, modelIdentifiers, invalidModelIdentifier
        }
        public init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            routingOverride = try values.decodeIfPresent(Bool.self, forKey: .routingOverride) ?? false
            customEndpoint = try values.decodeIfPresent(Bool.self, forKey: .customEndpoint) ?? false
            tlsDisabled = try values.decodeIfPresent(Bool.self, forKey: .tlsDisabled) ?? false
            tlsDowngradeAllowed = try values.decodeIfPresent(Bool.self, forKey: .tlsDowngradeAllowed) ?? false
            invalidTLSOptions = try values.decodeIfPresent(Bool.self, forKey: .invalidTLSOptions) ?? false
            clientCertificatesConfigured = try values.decodeIfPresent(
                Bool.self, forKey: .clientCertificatesConfigured) ?? false
            clientCertificateStatuses = try values.decodeIfPresent(
                Set<ClientCertificateStatus>.self, forKey: .clientCertificateStatuses) ?? []
            invalidClientCertificate = try values.decodeIfPresent(
                Bool.self, forKey: .invalidClientCertificate) ?? false
            customTrustConfiguration = try values.decodeIfPresent(Bool.self, forKey: .customTrustConfiguration) ?? false
            invalidTrustConfiguration = try values.decodeIfPresent(Bool.self, forKey: .invalidTrustConfiguration) ?? false
            locale = try values.decodeIfPresent([String: String].self, forKey: .locale) ?? [:]
            invalidLocaleKeys = try values.decodeIfPresent(Set<String>.self, forKey: .invalidLocaleKeys) ?? []
            autoMemoryDisabled = try values.decodeIfPresent(Bool.self, forKey: .autoMemoryDisabled)
            conflictingAutoMemorySetting = try values.decodeIfPresent(Bool.self, forKey: .conflictingAutoMemorySetting) ?? false
            customAutoMemoryDirectory = try values.decodeIfPresent(Bool.self, forKey: .customAutoMemoryDirectory) ?? false
            autoMemoryIndexEmpty = try values.decodeIfPresent(Bool.self, forKey: .autoMemoryIndexEmpty)
            authenticationModes = try values.decodeIfPresent(Set<String>.self, forKey: .authenticationModes) ?? []
            invalidAuthenticationMode = try values.decodeIfPresent(Bool.self, forKey: .invalidAuthenticationMode) ?? false
            modelIdentifiers = try values.decodeIfPresent(Set<String>.self, forKey: .modelIdentifiers) ?? []
            invalidModelIdentifier = try values.decodeIfPresent(Bool.self, forKey: .invalidModelIdentifier) ?? false
        }
        public mutating func markUnverifiable() {
            routingOverride = true
            customEndpoint = true
            tlsDisabled = true
            invalidTLSOptions = true
            invalidClientCertificate = true
            invalidTrustConfiguration = true
            invalidLocaleKeys.formUnion(SelectiveSettings.localeKeys)
            conflictingAutoMemorySetting = true
            customAutoMemoryDirectory = true
            autoMemoryIndexEmpty = nil
            invalidAuthenticationMode = true
            invalidModelIdentifier = true
        }
        public mutating func merge(_ other: Findings) {
            routingOverride = routingOverride || other.routingOverride
            customEndpoint = customEndpoint || other.customEndpoint
            tlsDisabled = tlsDisabled || other.tlsDisabled
            tlsDowngradeAllowed = tlsDowngradeAllowed || other.tlsDowngradeAllowed
            invalidTLSOptions = invalidTLSOptions || other.invalidTLSOptions
            clientCertificatesConfigured = clientCertificatesConfigured || other.clientCertificatesConfigured
            clientCertificateStatuses.formUnion(other.clientCertificateStatuses)
            invalidClientCertificate = invalidClientCertificate || other.invalidClientCertificate
            customTrustConfiguration = customTrustConfiguration || other.customTrustConfiguration
            invalidTrustConfiguration = invalidTrustConfiguration || other.invalidTrustConfiguration
            invalidLocaleKeys.formUnion(other.invalidLocaleKeys)
            if let value = other.autoMemoryDisabled {
                if let previous = autoMemoryDisabled, previous != value {
                    autoMemoryDisabled = nil
                    conflictingAutoMemorySetting = true
                } else if !conflictingAutoMemorySetting {
                    autoMemoryDisabled = value
                }
            }
            conflictingAutoMemorySetting = conflictingAutoMemorySetting || other.conflictingAutoMemorySetting
            if other.customAutoMemoryDirectory {
                customAutoMemoryDirectory = true
            }
            authenticationModes.formUnion(other.authenticationModes)
            invalidAuthenticationMode = invalidAuthenticationMode || other.invalidAuthenticationMode
            modelIdentifiers.formUnion(other.modelIdentifiers)
            invalidModelIdentifier = invalidModelIdentifier || other.invalidModelIdentifier
            if let empty = other.autoMemoryIndexEmpty {
                if let previous = autoMemoryIndexEmpty, previous != empty {
                    autoMemoryIndexEmpty = nil
                    conflictingAutoMemorySetting = true
                } else {
                    autoMemoryIndexEmpty = empty
                }
            }
            for (key, value) in other.locale {
                if let previous = locale[key], previous != value {
                    locale.removeValue(forKey: key)
                    invalidLocaleKeys.insert(key)
                } else if !invalidLocaleKeys.contains(key) {
                    locale[key] = value
                }
            }
        }
    }
    private static let localeKeys = Set(["TZ", "LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE"])
    private static let autoMemoryKey = "CLAUDE_CODE_DISABLE_AUTO_MEMORY"
    private static let routingKeys = Set([
        "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY",
        "no_proxy", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "CLAUDE_CODE_CERT_STORE",
        "CLAUDE_CODE_CLIENT_CERT", "CLAUDE_CODE_CLIENT_KEY", "NODE_TLS_REJECT_UNAUTHORIZED",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_USE_SYSTEM_CA", "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_PROCESS_WRAPPER"
    ])
    private static let trustConfigurationKeys = Set([
        "NODE_EXTRA_CA_CERTS", "CLAUDE_CODE_CERT_STORE", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_USE_SYSTEM_CA"
    ])
    private static func certificateStatus(path: String) -> ClientCertificateStatus? {
        ClientCertificate.inspect(path: path)
    }
    public static let proxyRoutingKeys = Set([
        "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY",
        "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY",
    ])

    /// Inspect Node's inherited runtime options without retaining or forwarding
    /// their contents. Only protocol minimums below TLS 1.2 are reported.
    public static func nodeOptionsFindings(_ value: String) -> Findings {
        var findings = Findings()
        guard value.utf8.count <= 8_192, !value.utf8.contains(0),
              let tokens = nodeOptionTokens(value) else {
            findings.invalidTLSOptions = true
            return findings
        }
        findings.tlsDowngradeAllowed = tokens.contains("--tls-min-v1.0") ||
            tokens.contains("--tls-min-v1.1")
        return findings
    }

    private static func nodeOptionTokens(_ value: String) -> [String]? {
        var tokens: [String] = []
        var token = ""
        var quote: Character?
        var escaped = false
        for character in value {
            if escaped {
                token.append(character)
                escaped = false
            } else if character == "\\" {
                escaped = true
            } else if let activeQuote = quote {
                if character == activeQuote { quote = nil }
                else { token.append(character) }
            } else if character == "\"" || character == "'" {
                quote = character
            } else if character.isWhitespace {
                if !token.isEmpty { tokens.append(token); token = "" }
            } else {
                token.append(character)
            }
        }
        guard quote == nil, !escaped else { return nil }
        if !token.isEmpty { tokens.append(token) }
        return tokens
    }

    public static func paths(environment: [String: String], workingDirectory: String?,
                             additionalSettingsPath: String? = nil) -> [String] {
        var paths: [String] = []
        // Claude Code administrator policy is delivered through managed
        // settings. Track both the single-file form and drop-in directory so
        // a newly installed policy cannot silently bypass an active session.
        paths.append("/Library/Application Support/ClaudeCode/managed-settings.json")
        paths.append("/Library/Application Support/ClaudeCode/managed-settings.d")
        if let config = environment["CLAUDE_CONFIG_DIR"], config.hasPrefix("/"),
           config.utf8.count <= 4096, !config.utf8.contains(0) {
            paths.append(URL(fileURLWithPath: config).appendingPathComponent("settings.json").path)
        } else if environment["CLAUDE_CONFIG_DIR"] == nil,
                  let home = environment["HOME"], home.hasPrefix("/"), home.utf8.count <= 4096,
                  !home.utf8.contains(0) {
            paths.append(URL(fileURLWithPath: home).appendingPathComponent(".claude/settings.json").path)
        }
        if let cwd = workingDirectory, cwd.hasPrefix("/"), cwd.utf8.count <= 4096, !cwd.utf8.contains(0) {
            let root = URL(fileURLWithPath: cwd).appendingPathComponent(".claude")
            paths.append(root.appendingPathComponent("settings.json").path)
            paths.append(root.appendingPathComponent("settings.local.json").path)
        }
        if let additionalSettingsPath, additionalSettingsPath.hasPrefix("/"),
           additionalSettingsPath.utf8.count <= 4096, !additionalSettingsPath.utf8.contains(0) {
            paths.append(additionalSettingsPath)
        }
        if let workingDirectory,
           let memoryPath = defaultAutoMemoryDirectoryPath(environment: environment,
                                                          workingDirectory: workingDirectory) {
            paths.append(memoryPath)
        }
        return Array(Set(paths)).sorted()
    }
    public static func inspect(environment: [String: String], workingDirectory: String?,
                               additionalSettingsPath: String? = nil) -> Findings {
        inspectContext(environment: environment, workingDirectory: workingDirectory,
                       additionalSettingsPath: additionalSettingsPath).findings
    }

    public static func inspectContext(environment: [String: String], workingDirectory: String?,
                                      additionalSettingsPath: String? = nil,
                                      commandLineRoutingEnvironment: [String: String] = [:],
                                      trustedEndpoints: [String] = []) -> Inspection {
        var result = Findings()
        var routingEnvironment: [String: String] = [:]
        var routingConflict = false
        var autoMemoryDirectoryPath: String?
        func mergeRouting(_ values: [String: String], _ hasConflict: Bool) {
            routingConflict = routingConflict || hasConflict
            for (key, value) in values {
                if let previous = routingEnvironment[key], previous != value {
                    routingConflict = true
                } else {
                    routingEnvironment[key] = value
                }
            }
        }
        let userSettingsPath: String? = {
            if let config = environment["CLAUDE_CONFIG_DIR"], config.hasPrefix("/") {
                return URL(fileURLWithPath: config).appendingPathComponent("settings.json").path
            }
            if let home = environment["HOME"], home.hasPrefix("/") {
                return URL(fileURLWithPath: home).appendingPathComponent(".claude/settings.json").path
            }
            return nil
        }()
        let projectSettingsRoot = workingDirectory.map {
            URL(fileURLWithPath: $0).appendingPathComponent(".claude").standardizedFileURL.path + "/"
        }
        func mergeFile(_ path: String) {
            guard let item = inspectFileContext(path: path, trustedEndpoints: trustedEndpoints) else {
                result.markUnverifiable()
                routingConflict = true
                return
            }
            let isCommandLineSettings = additionalSettingsPath == path
            let isManagedSettings = path.hasPrefix("/Library/Application Support/ClaudeCode/managed-settings")
            let isProjectSettings = projectSettingsRoot.map { path.hasPrefix($0) } ?? false
            if item.findings.customAutoMemoryDirectory &&
                isProjectSettings && !isCommandLineSettings && !isManagedSettings {
                // Project-supplied custom paths are trust-sensitive. Do not
                // read them as effective auto memory without a trust adapter.
                result.conflictingAutoMemorySetting = true
            } else if item.findings.customAutoMemoryDirectory &&
                        path != userSettingsPath && !isCommandLineSettings && !isManagedSettings {
                result.conflictingAutoMemorySetting = true
            } else if item.findings.customAutoMemoryDirectory {
                guard let incomingPath = item.autoMemoryDirectoryPath else {
                    result.conflictingAutoMemorySetting = true
                    result.merge(item.findings)
                    mergeRouting(item.routingEnvironment, item.routingConflict)
                    return
                }
                if let previousPath = autoMemoryDirectoryPath, previousPath != incomingPath {
                    autoMemoryDirectoryPath = nil
                    result.conflictingAutoMemorySetting = true
                } else {
                    autoMemoryDirectoryPath = incomingPath
                }
            }
            result.merge(item.findings)
            mergeRouting(item.routingEnvironment, item.routingConflict)
        }
        for path in paths(environment: environment, workingDirectory: workingDirectory,
                          additionalSettingsPath: additionalSettingsPath) {
            var info = stat()
            guard lstat(path, &info) == 0 else {
                if errno != ENOENT { result.markUnverifiable() }
                continue
            }
            if (info.st_mode & S_IFMT) == S_IFDIR {
                guard let children = managedSettingsFiles(in: path) else {
                    result.markUnverifiable()
                    routingConflict = true
                    continue
                }
                for child in children {
                    mergeFile(child)
                }
            } else {
                mergeFile(path)
            }
        }
        let managed = inspectManagedPreferencesContext(trustedEndpoints: trustedEndpoints)
        result.merge(managed.findings)
        mergeRouting(managed.routingEnvironment, managed.routingConflict)
        mergeRouting(commandLineRoutingEnvironment, false)
        // Claude Code defaults auto-memory to enabled when no applicable
        // setting or environment override disables it.
        if result.autoMemoryDisabled == nil, !result.conflictingAutoMemorySetting {
            result.autoMemoryDisabled = false
        }
        if !result.customAutoMemoryDirectory, result.autoMemoryDisabled != true,
           !result.conflictingAutoMemorySetting {
            result.autoMemoryIndexEmpty = autoMemoryIndexCensus(environment: environment,
                                                               workingDirectory: workingDirectory)
        } else if result.customAutoMemoryDirectory, let path = autoMemoryDirectoryPath,
                  !result.conflictingAutoMemorySetting, result.autoMemoryDisabled != true {
            result.autoMemoryIndexEmpty = autoMemoryIndexCensus(path: path, environment: environment)
        }
        return Inspection(findings: result, routingEnvironment: routingEnvironment,
                          routingConflict: routingConflict)
    }

    public static func modelEnvironment(_ environment: [String: String]) -> Findings {
        var result = Findings()
        for key in ["ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_MODEL"] {
            guard let value = environment[key] else { continue }
            if ClaudeModelLifecycle.isValidIdentifier(value) {
                result.modelIdentifiers.insert(value)
            } else {
                result.invalidModelIdentifier = true
            }
        }
        return result
    }

    public static func modelArgument(_ value: String) -> Findings {
        var result = Findings()
        if ClaudeModelLifecycle.isValidIdentifier(value) {
            result.modelIdentifiers.insert(value)
        } else {
            result.invalidModelIdentifier = true
        }
        return result
    }

    /// Performs a metadata-only census of Claude's default auto-memory folder.
    /// Directory names are used transiently by readdir/fstatat and are never
    /// persisted, returned, or logged; no memory file is opened.
    private static func autoMemoryIndexCensus(environment: [String: String],
                                              workingDirectory: String?) -> Bool? {
        guard let workingDirectory else { return nil }
        guard let path = defaultAutoMemoryDirectoryPath(environment: environment,
                                                       workingDirectory: workingDirectory) else { return nil }
        return countMemoryEntries(path)
    }

    public static func autoMemoryIndexCensus(path: String, environment: [String: String]) -> Bool? {
        let expanded: String
        if path.hasPrefix("~/") {
            guard let home = environment["HOME"], home.hasPrefix("/"),
                  home.utf8.count <= 4096, !home.utf8.contains(0) else { return nil }
            expanded = home + String(path.dropFirst())
        } else {
            expanded = path
        }
        guard expanded.hasPrefix("/"), expanded.utf8.count <= 4096,
              !expanded.utf8.contains(0) else { return nil }
        return countMemoryEntries(canonicalPath(expanded) ?? expanded)
    }

    private static func defaultAutoMemoryDirectoryPath(environment: [String: String],
                                                       workingDirectory: String) -> String? {
        guard workingDirectory.hasPrefix("/"), workingDirectory.utf8.count <= 4096,
              !workingDirectory.utf8.contains(0),
              let canonicalCWD = canonicalPath(workingDirectory) else { return nil }
        let config = environment["CLAUDE_CONFIG_DIR"]
        let home = environment["HOME"] ?? NSHomeDirectory()
        guard let baseInput = config.flatMap({ $0.hasPrefix("/") ? $0 : nil }) ?? Optional(home),
              baseInput.hasPrefix("/"), baseInput.utf8.count <= 4096,
              let base = canonicalPath(baseInput) else { return nil }
        if let configuredName = environment["CLAUDE_CODE_PROJECT_DIR_NAME"], config != nil {
            guard validProjectDirectoryName(configuredName) else { return nil }
            return URL(fileURLWithPath: base)
                .appendingPathComponent("projects")
                .appendingPathComponent(configuredName)
                .appendingPathComponent("memory").path
        }
        guard let projectRoot = projectRootForMemory(canonicalCWD) else { return nil }
        let key = projectRoot.replacingOccurrences(of: #"[^A-Za-z0-9]"#,
                                                   with: "-", options: .regularExpression)
        // Long keys use Claude's internal hash function, which is deliberately
        // not guessed here.
        guard key.utf8.count <= 200 else { return nil }
        let storageRoot = URL(fileURLWithPath: base)
            .appendingPathComponent(config == nil ? ".claude" : "")
        return storageRoot.appendingPathComponent("projects")
            .appendingPathComponent(key).appendingPathComponent("memory").path
    }

    private static func validProjectDirectoryName(_ name: String) -> Bool {
        guard !name.isEmpty, name != ".", name != "..", name.utf8.count <= 255,
              !name.contains("/"), !name.contains("\\"), !name.utf8.contains(0) else { return false }
        return name.unicodeScalars.allSatisfy {
            !CharacterSet.controlCharacters.contains($0)
        }
    }

    private static func canonicalPath(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func projectRootForMemory(_ cwd: String) -> String? {
        var current = URL(fileURLWithPath: cwd).standardizedFileURL
        while current.path != "/" {
            let marker = current.appendingPathComponent(".git").path
            var info = stat()
            if lstat(marker, &info) == 0 {
                // Worktree .git files and linked checkouts can use Claude's
                // canonical working-copy root; leave those cases unresolved.
                guard (info.st_mode & S_IFMT) == S_IFDIR else { return nil }
                return current.path
            }
            current.deleteLastPathComponent()
        }
        return cwd
    }

    private static func countMemoryEntries(_ path: String) -> Bool? {
        guard path.hasPrefix("/"), path.utf8.count <= 4096 else { return nil }
        let components = path.split(separator: "/").map(String.init)
        let rootFD = open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY)
        guard rootFD >= 0 else { return nil }
        var fd = rootFD
        defer { close(fd) }
        for component in components {
            guard !component.isEmpty, component != ".", component != "..",
                  !component.contains("/") else { return nil }
            let next = openat(fd, component, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
            guard next >= 0 else {
                if errno == ENOENT { return true }
                return nil
            }
            close(fd)
            fd = next
        }
        var directoryInfo = stat()
        guard fstat(fd, &directoryInfo) == 0,
              (directoryInfo.st_mode & S_IFMT) == S_IFDIR,
              directoryInfo.st_uid == getuid() else { return nil }
        let scanFD = dup(fd)
        guard scanFD >= 0, let directory = fdopendir(scanFD) else {
            if scanFD >= 0 { close(scanFD) }
            return nil
        }
        defer { closedir(directory) }
        var count = 0
        while true {
            errno = 0
            guard let entry = readdir(directory) else {
                guard errno == 0 else { return nil }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(NAME_MAX) + 1) {
                    String(cString: $0)
                }
            }
            if name == "." || name == ".." { continue }
            var item = stat()
            guard fstatat(fd, name, &item, AT_SYMLINK_NOFOLLOW) == 0,
                  item.st_uid == getuid() else { return nil }
            let kind = item.st_mode & S_IFMT
            guard kind == S_IFREG else { return nil }
            guard name.lowercased().hasSuffix(".md") else { continue }
            count += 1
            guard count <= 512 else { return nil }
        }
        return count == 0
    }

    /// macOS configuration profiles expose Claude Code policy through the
    /// managed preferences domain. Read only the selected `env` fields.
    public static func inspectManagedPreferences() -> Findings {
        inspectManagedPreferencesContext().findings
    }

    public static func inspectManagedPreferencesContext(trustedEndpoints: [String] = []) -> Inspection {
        let domainName = "com.anthropic.claudecode" as CFString
        let scopes: [(CFString, CFString)] = [
            (kCFPreferencesCurrentUser, kCFPreferencesAnyHost),
            (kCFPreferencesCurrentUser, kCFPreferencesCurrentHost),
            (kCFPreferencesAnyUser, kCFPreferencesAnyHost),
            (kCFPreferencesAnyUser, kCFPreferencesCurrentHost)
        ]
        var combined = Findings()
        var routingEnvironment: [String: String] = [:]
        var routingConflict = false
        for (user, host) in scopes {
            guard let domain = CFPreferencesCopyMultiple(nil, domainName, user, host) as? [String: Any] else { continue }
            let environment = domain["env"] as? [String: Any] ?? [:]
            var result = Findings()
            if let model = domain["model"] {
                guard let value = model as? String, ClaudeModelLifecycle.isValidIdentifier(value) else {
                    result.invalidModelIdentifier = true
                    combined.merge(result)
                    continue
                }
                result.modelIdentifiers.insert(value)
            }
            for (key, rawValue) in environment {
                if proxyRoutingKeys.contains(key) {
                    guard let value = rawValue as? String, value.utf8.count <= 8192,
                          !value.utf8.contains(0) else {
                        routingConflict = true
                        continue
                    }
                    if let previous = routingEnvironment[key], previous != value { routingConflict = true }
                    else { routingEnvironment[key] = value }
                }
                if key == "ANTHROPIC_API_KEY" {
                    result.authenticationModes.insert("api-key")
                } else if key == "ANTHROPIC_AUTH_TOKEN" {
                    result.authenticationModes.insert("auth-token")
                } else if key == "CLAUDE_CODE_USE_BEDROCK" || key == "CLAUDE_CODE_USE_VERTEX" {
                    let enabled: Bool?
                    if let value = rawValue as? String {
                        switch value.lowercased() {
                        case "1", "true", "yes", "on": enabled = true
                        case "0", "false", "no", "off": enabled = false
                        default: enabled = nil
                        }
                    } else if let value = rawValue as? NSNumber {
                        enabled = value.intValue == 1 ? true : (value.intValue == 0 ? false : nil)
                    } else { enabled = nil }
                    guard let enabled else {
                        result.invalidAuthenticationMode = true
                        continue
                    }
                    if enabled {
                        result.authenticationModes.insert(key == "CLAUDE_CODE_USE_BEDROCK" ? "bedrock" : "vertex")
                    }
                } else if key == "ANTHROPIC_MODEL" || key == "ANTHROPIC_DEFAULT_MODEL" {
                    guard let value = rawValue as? String,
                          ClaudeModelLifecycle.isValidIdentifier(value) else {
                        result.invalidModelIdentifier = true
                        continue
                    }
                    result.modelIdentifiers.insert(value)
                } else if key == "CLAUDE_CODE_CLIENT_CERT" {
                    result.routingOverride = true
                    result.clientCertificatesConfigured = true
                    guard let path = rawValue as? String, let status = certificateStatus(path: path) else {
                        result.invalidClientCertificate = true
                        continue
                    }
                    result.clientCertificateStatuses.insert(status)
                } else if key == "NODE_OPTIONS" {
                    guard let value = rawValue as? String, value.utf8.count <= 8_192,
                          !value.utf8.contains(0) else {
                        result.invalidTLSOptions = true
                        continue
                    }
                    result.merge(nodeOptionsFindings(value))
                } else if routingKeys.contains(key) {
                    result.routingOverride = true
                    if key == "ANTHROPIC_BASE_URL" {
                        guard let value = rawValue as? String else {
                            result.customEndpoint = true
                            continue
                        }
                        result.customEndpoint = !TrustedEndpoint.isTrusted(value, allowlist: trustedEndpoints)
                    }
                    if key == "NODE_TLS_REJECT_UNAUTHORIZED" {
                        if let value = rawValue as? String, value == "0" { result.tlsDisabled = true }
                        else if let value = rawValue as? NSNumber, value.intValue == 0 { result.tlsDisabled = true }
                    }
                    if trustConfigurationKeys.contains(key) { result.customTrustConfiguration = true }
                } else if localeKeys.contains(key) {
                    guard let value = rawValue as? String else {
                        result.invalidLocaleKeys.insert(key)
                        continue
                    }
                    let valid = key == "TZ"
                        ? value.utf8.count <= 128 && TimeZone(identifier: value) != nil
                        : Parser.validLocale(value)
                    if valid { result.locale[key] = value }
                    else { result.invalidLocaleKeys.insert(key) }
                }
            }
            combined.merge(result)
        }
        return Inspection(findings: combined, routingEnvironment: routingEnvironment,
                          routingConflict: routingConflict)
    }

    /// Only regular JSON files are accepted from managed drop-in directories.
    /// A malformed or unsafe entry makes the resulting policy unknown.
    static func managedSettingsFiles(in path: String) -> [String]? {
        let directoryFD = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
        guard directoryFD >= 0 else { return nil }
        defer { close(directoryFD) }
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: path),
              names.count <= 128 else { return nil }
        var result: [String] = []
        for name in names.sorted() {
            guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
                  name.utf8.count <= 255 else { return nil }
            // Ignore unrelated files, but reject unsafe JSON entries.
            guard name.hasSuffix(".json") else { continue }
            let child = URL(fileURLWithPath: path).appendingPathComponent(name).path
            var info = stat()
            guard lstat(child, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
            result.append(child)
        }
        return result
    }
    public static func inspectJSON(_ data: Data) -> Findings? {
        inspectJSONContext(data).map(\.findings)
    }

    public static func inspectJSONContext(_ data: Data, trustedEndpoints: [String] = []) -> Inspection? {
        guard !data.isEmpty, data.count <= 2_000_000 else { return nil }
        var parser = Parser(data: data, trustedEndpoints: trustedEndpoints)
        guard parser.parse() else { return nil }
        return Inspection(findings: parser.findings, routingEnvironment: parser.routingEnvironment,
                          routingConflict: parser.routingConflict,
                          autoMemoryDirectoryPath: parser.autoMemoryDirectoryPath)
    }

    public static func inspectFile(path: String) -> Findings? {
        inspectFileContext(path: path)?.findings
    }

    public static func inspectFileContext(path: String, trustedEndpoints: [String] = []) -> Inspection? {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              (0...2_000_000).contains(info.st_size) else { return nil }
        var parser = Parser(fd: fd, trustedEndpoints: trustedEndpoints)
        guard parser.parse() else { return nil }
        return Inspection(findings: parser.findings, routingEnvironment: parser.routingEnvironment,
                          routingConflict: parser.routingConflict,
                          autoMemoryDirectoryPath: parser.autoMemoryDirectoryPath)
    }

    private enum Scope { case root, environment, other }
    private struct Parser {
        let fd: Int32?
        let data: Data?
        var dataOffset = 0
        var lookahead: UInt8?
        var count = 0
        var failed = false
        var captureOverflowed = false
        var clientCertificateInspectionCount = 0
        var findings = Findings()
        var autoMemoryDirectoryPath: String?
        var routingEnvironment: [String: String] = [:]
        var routingConflict = false
        let trustedEndpoints: [String]

        init(fd: Int32, trustedEndpoints: [String]) {
            self.fd = fd
            data = nil
            self.trustedEndpoints = trustedEndpoints
        }
        init(data: Data, trustedEndpoints: [String]) {
            fd = nil
            self.data = data
            self.trustedEndpoints = trustedEndpoints
        }
        mutating func next() -> UInt8? {
            if let value = lookahead { lookahead = nil; return value }
            guard count < 2_000_001 else { failed = true; return nil }
            if let data {
                guard dataOffset < data.count else { return nil }
                let value = data[dataOffset]
                dataOffset += 1
                count += 1
                return value
            }
            while true {
                var byte: UInt8 = 0
                guard let fd else { failed = true; return nil }
                let n = Darwin.read(fd, &byte, 1)
                if n < 0 && errno == EINTR { continue }
                if n < 0 { failed = true; return nil }
                if n == 0 { return nil }
                count += 1
                return byte
            }
        }
        mutating func peek() -> UInt8? {
            if lookahead == nil { lookahead = next() }
            return lookahead
        }
        mutating func whitespace() {
            while let value = peek(), [9, 10, 13, 32].contains(value) { _ = next() }
        }
        mutating func parse() -> Bool {
            whitespace()
            guard peek() == 123, value(scope: .root, depth: 0) else { return false }
            whitespace()
            return peek() == nil && !failed && count <= 2_000_000
        }
        // Only keys and the harmless NODE_TLS_REJECT_UNAUTHORIZED value are
        // captured. Other JSON strings are validated without retaining bytes.
        mutating func string(capture: Bool, limit: Int = 4096) -> String? {
            guard next() == 34 else { return nil }
            var raw = [UInt8]()
            var recording = capture
            if capture { raw.append(34) }
            while let c = next() {
                if recording {
                    if raw.count >= limit {
                        recording = false
                        captureOverflowed = true
                        raw.removeAll(keepingCapacity: false)
                    }
                }
                if recording {
                    raw.append(c)
                }
                if c == 34 {
                    guard recording else { return "" }
                    guard let values = try? JSONDecoder().decode([String].self, from: Data([91] + raw + [93]))
                    else { return nil }
                    return values.first
                }
                guard c >= 32 else { return nil }
                if c == 92 {
                    guard let escape = next() else { return nil }
                    if recording { raw.append(escape) }
                    if escape == 117 {
                        for _ in 0..<4 {
                            guard let hex = next(), (48...57).contains(hex) ||
                                (65...70).contains(hex) || (97...102).contains(hex) else { return nil }
                            if recording { raw.append(hex) }
                        }
                    } else if ![34, 92, 47, 98, 102, 110, 114, 116].contains(escape) {
                        return nil
                    }
                }
            }
            return nil
        }
        mutating func value(scope: Scope, depth: Int) -> Bool {
            guard depth < 64 else { return false }
            whitespace()
            guard let c = peek() else { return false }
            if c == 123 {
                _ = next(); whitespace()
                if peek() == 125 { _ = next(); return true }
                while true {
                    guard let key = string(capture: true) else { return false }
                    whitespace()
                    guard next() == 58 else { return false }
                    whitespace()
                    if scope == .environment && key == "NODE_OPTIONS" {
                        if peek() == 34 {
                            captureOverflowed = false
                            guard let value = string(capture: true, limit: 8_192) else { return false }
                            let overflowed = captureOverflowed
                            captureOverflowed = false
                            if overflowed { findings.invalidTLSOptions = true }
                            else { findings.merge(SelectiveSettings.nodeOptionsFindings(value)) }
                        } else {
                            findings.invalidTLSOptions = true
                            guard value(scope: .other, depth: depth + 1) else { return false }
                        }
                    } else if scope == .environment && key == "CLAUDE_CODE_CLIENT_CERT" {
                        findings.routingOverride = true
                        findings.clientCertificatesConfigured = true
                        if peek() != 34 {
                            findings.invalidClientCertificate = true
                            guard value(scope: .other, depth: depth + 1) else { return false }
                        } else if clientCertificateInspectionCount >= 8 {
                            findings.invalidClientCertificate = true
                            guard value(scope: .other, depth: depth + 1) else { return false }
                        } else {
                            clientCertificateInspectionCount += 1
                            guard let path = string(capture: true, limit: 4097) else { return false }
                            if let status = SelectiveSettings.certificateStatus(path: path) {
                                findings.clientCertificateStatuses.insert(status)
                            } else {
                                findings.invalidClientCertificate = true
                            }
                        }
                    } else if scope == .environment && SelectiveSettings.routingKeys.contains(key) {
                        findings.routingOverride = true
                        if key == "ANTHROPIC_BASE_URL" {
                            if peek() == 34, let endpoint = string(capture: true, limit: 2048) {
                                findings.customEndpoint = !TrustedEndpoint.isTrusted(
                                    endpoint, allowlist: trustedEndpoints)
                            } else {
                                findings.customEndpoint = true
                                guard value(scope: .other, depth: depth + 1) else { return false }
                            }
                        } else if SelectiveSettings.trustConfigurationKeys.contains(key) {
                            findings.customTrustConfiguration = true
                            guard value(scope: .other, depth: depth + 1) else { return false }
                        } else if SelectiveSettings.proxyRoutingKeys.contains(key) {
                            guard peek() == 34, let value = string(capture: true, limit: 8192) else {
                                routingConflict = true
                                guard value(scope: .other, depth: depth + 1) else { return false }
                                continue
                            }
                            if value.isEmpty { routingConflict = true }
                            if let previous = routingEnvironment[key], previous != value { routingConflict = true }
                            else { routingEnvironment[key] = value }
                        } else if key == "NODE_TLS_REJECT_UNAUTHORIZED", peek() == 34 {
                            guard let value = string(capture: true, limit: 16) else { return false }
                            if value == "0" { findings.tlsDisabled = true }
                        } else if !value(scope: .other, depth: depth + 1) { return false }
                    } else if scope == .root && key == "model" {
                        if peek() == 34 {
                            guard let model = string(capture: true, limit: 129) else { return false }
                            if ClaudeModelLifecycle.isValidIdentifier(model) {
                                findings.modelIdentifiers.insert(model)
                            } else {
                                findings.invalidModelIdentifier = true
                            }
                        } else {
                            findings.invalidModelIdentifier = true
                            guard value(scope: .other, depth: depth + 1) else { return false }
                        }
                    } else if scope == .root && key == "autoMemoryEnabled" {
                        if peek() == 116 {
                            guard value(scope: .other, depth: depth + 1) else { return false }
                            findings.autoMemoryDisabled = false
                        } else if peek() == 102 {
                            guard value(scope: .other, depth: depth + 1) else { return false }
                            findings.autoMemoryDisabled = true
                        } else {
                            guard value(scope: .other, depth: depth + 1) else { return false }
                            findings.conflictingAutoMemorySetting = true
                        }
                    } else if scope == .root && key == "autoMemoryDirectory" {
                        findings.customAutoMemoryDirectory = true
                        if peek() == 34 {
                            guard let path = string(capture: true, limit: 4096) else { return false }
                            autoMemoryDirectoryPath = path
                        } else {
                            findings.conflictingAutoMemorySetting = true
                            guard value(scope: .other, depth: depth + 1) else { return false }
                        }
                    } else if scope == .root && key == "apiKeyHelper" {
                        findings.authenticationModes.insert("api-key-helper")
                        guard value(scope: .other, depth: depth + 1) else { return false }
                    } else if scope == .environment &&
                                ["ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_MODEL"].contains(key) {
                        if peek() == 34 {
                            guard let model = string(capture: true, limit: 129) else { return false }
                            if ClaudeModelLifecycle.isValidIdentifier(model) {
                                findings.modelIdentifiers.insert(model)
                            } else {
                                findings.invalidModelIdentifier = true
                            }
                        } else {
                            findings.invalidModelIdentifier = true
                            guard value(scope: .other, depth: depth + 1) else { return false }
                        }
                    } else if scope == .environment &&
                                ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"].contains(key) {
                        findings.authenticationModes.insert(key == "ANTHROPIC_API_KEY" ? "api-key" : "auth-token")
                        guard value(scope: .other, depth: depth + 1) else { return false }
                    } else if scope == .environment &&
                                ["CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX"].contains(key) {
                        if peek() != 34 {
                            findings.invalidAuthenticationMode = true
                            guard value(scope: .other, depth: depth + 1) else { return false }
                        } else {
                            guard let value = string(capture: true, limit: 16) else {
                                return false
                            }
                            switch value.lowercased() {
                            case "1", "true", "yes", "on":
                                findings.authenticationModes.insert(key == "CLAUDE_CODE_USE_BEDROCK" ? "bedrock" : "vertex")
                            case "0", "false", "no", "off": break
                            default: findings.invalidAuthenticationMode = true
                            }
                        }
                    } else if scope == .environment && key == SelectiveSettings.autoMemoryKey {
                        guard peek() == 34, let value = string(capture: true, limit: 16) else {
                            return false
                        }
                        switch value.lowercased() {
                        case "1", "true", "yes", "on": findings.autoMemoryDisabled = true
                        case "0", "false", "no", "off": findings.autoMemoryDisabled = false
                        default: findings.conflictingAutoMemorySetting = true
                        }
                    } else if scope == .environment && SelectiveSettings.localeKeys.contains(key) {
                        guard peek() == 34 else {
                            guard value(scope: .other, depth: depth + 1) else { return false }
                            findings.invalidLocaleKeys.insert(key)
                            whitespace()
                            guard let separator = next() else { return false }
                            if separator == 125 { return true }
                            guard separator == 44 else { return false }
                            whitespace()
                            continue
                        }
                        guard let value = string(capture: true, limit: 256) else { return false }
                        let valid = key == "TZ"
                            ? value.utf8.count <= 128 && TimeZone(identifier: value) != nil
                            : Self.validLocale(value)
                        if valid { findings.locale[key] = value }
                        else { findings.invalidLocaleKeys.insert(key) }
                    } else {
                        let childScope: Scope = scope == .root && key == "env" ? .environment : .other
                        if !value(scope: childScope, depth: depth + 1) { return false }
                    }
                    whitespace()
                    guard let separator = next() else { return false }
                    if separator == 125 { return true }
                    guard separator == 44 else { return false }
                    whitespace()
                }
            }
            if c == 91 {
                _ = next(); whitespace()
                if peek() == 93 { _ = next(); return true }
                while true {
                    guard value(scope: .other, depth: depth + 1) else { return false }
                    whitespace()
                    guard let separator = next() else { return false }
                    if separator == 93 { return true }
                    guard separator == 44 else { return false }
                }
            }
            if c == 34 { return string(capture: false) != nil }
            if c == 116 || c == 102 || c == 110 {
                let literal = c == 116 ? "true" : (c == 102 ? "false" : "null")
                for expected in literal.utf8 {
                    guard next() == expected else { return false }
                }
                return true
            }
            if peek() == 45 { _ = next() }
            guard let first = next() else { return false }
            if first != 48 {
                guard (49...57).contains(first) else { return false }
                while let digit = peek(), (48...57).contains(digit) { _ = next() }
            }
            if peek() == 46 {
                _ = next()
                guard let digit = next(), (48...57).contains(digit) else { return false }
                while let digit = peek(), (48...57).contains(digit) { _ = next() }
            }
            if peek() == 101 || peek() == 69 {
                _ = next()
                if peek() == 43 || peek() == 45 { _ = next() }
                guard let digit = next(), (48...57).contains(digit) else { return false }
                while let digit = peek(), (48...57).contains(digit) { _ = next() }
            }
            return true
        }
        static func validLocale(_ value: String) -> Bool {
            guard !value.isEmpty, value.utf8.count <= 64 else { return false }
            return value.range(of: #"^(?:[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*|C|POSIX)(?:\.[A-Za-z0-9_-]{1,16})?$"#,
                               options: .regularExpression) != nil
        }
    }
}
