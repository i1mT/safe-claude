import Darwin
import Foundation
import XCTest
@testable import GuardCore

final class SelectiveSettingsTests: XCTestCase {
    func testNodeOptionsRetainOnlyLegacyTLSMinimumSignal() throws {
        let weak = SelectiveSettings.nodeOptionsFindings(#"--trace-warnings "--tls-min-v1.0" --max-old-space-size=4096"#)
        XCTAssertTrue(weak.tlsDowngradeAllowed)
        XCTAssertFalse(String(describing: weak).contains("max-old-space-size"))

        let safe = SelectiveSettings.nodeOptionsFindings("--tls-min-v1.2 --trace-warnings")
        XCTAssertFalse(safe.tlsDowngradeAllowed)
        let malformed = SelectiveSettings.nodeOptionsFindings(#"--require "unterminated"#)
        XCTAssertTrue(malformed.invalidTLSOptions)
    }

    func testNodeOptionsAreReducedToBooleanInSettingsAndMalformedValuesStayUnknown() throws {
        let weak = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            #"{"env":{"NODE_OPTIONS":"--tls-min-v1.1 --require=/private/plugin.js"}}"#.utf8)))
        XCTAssertTrue(weak.tlsDowngradeAllowed)
        let serialized = String(data: try JSONEncoder().encode(weak), encoding: .utf8)!
        XCTAssertFalse(serialized.contains("private/plugin.js"))
        XCTAssertFalse(serialized.contains("--tls-min-v1.1"))

        let malformed = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            #"{"env":{"NODE_OPTIONS":false}}"#.utf8)))
        XCTAssertTrue(malformed.invalidTLSOptions)
        let empty = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            #"{"env":{"NODE_OPTIONS":""}}"#.utf8)))
        XCTAssertFalse(empty.invalidTLSOptions)
        XCTAssertFalse(empty.tlsDowngradeAllowed)
        let oversized = String(repeating: "x", count: 8_200)
        let unreadable = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            (#"{"env":{"NODE_OPTIONS":"--tls-min-v1.0 "# + oversized + #""}}"#).utf8)))
        XCTAssertTrue(unreadable.invalidTLSOptions)
    }

    func testFindsOnlySelectedEnvironmentSignals() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("settings.json")
        let json = #"""
        {"env":{"ANTHROPIC_API_KEY":"private-credential-sentinel",
          "https_proxy":"http://proxy-user:proxy-secret@example.test",
          "ANTHROPIC_BASE_URL":"https://fixture.test",
          "\u004eODE_TLS_REJECT_UNAUTHORIZED":"\u0030"},
         "unrelated":{"nested":["private-credential-sentinel", 12.5e-2, true, null]}}
        """#
        try Data(json.utf8).write(to: file)
        let findings = try XCTUnwrap(SelectiveSettings.inspectFile(path: file.path))
        XCTAssertTrue(findings.routingOverride)
        XCTAssertTrue(findings.customEndpoint)
        XCTAssertTrue(findings.tlsDisabled)
        let description = String(describing: findings)
        XCTAssertFalse(description.contains("private-credential-sentinel"))
        XCTAssertFalse(description.contains("proxy-secret"))
    }
    func testParsesInlineSettingsWithoutRetainingUnrelatedValues() throws {
        let source = #"""
        {"env":{"ANTHROPIC_API_KEY":"inline-secret",
          "ANTHROPIC_BASE_URL":"https://custom.example",
          "TZ":"Asia/Tokyo","LANG":"ja_JP.UTF-8"},
         "unrelated":{"token":"must-not-escape"}}
        """#
        let findings = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(source.utf8)))
        XCTAssertTrue(findings.customEndpoint)
        XCTAssertEqual(findings.locale["TZ"], "Asia/Tokyo")
        XCTAssertEqual(findings.locale["LANG"], "ja_JP.UTF-8")
        let serialized = String(data: try JSONEncoder().encode(findings), encoding: .utf8)!
        XCTAssertFalse(serialized.contains("inline-secret"))
        XCTAssertFalse(serialized.contains("must-not-escape"))
        XCTAssertNil(SelectiveSettings.inspectJSON(Data(#"{"env":{"https_proxy":"x"}"#.utf8)))
    }
    func testTrustedEndpointIsClassifiedLocallyForInlineAndFileSettings() throws {
        let source = #"{"env":{"ANTHROPIC_BASE_URL":"https://Gateway.Example:443/"}}"#
        let trusted = try XCTUnwrap(SelectiveSettings.inspectJSONContext(
            Data(source.utf8), trustedEndpoints: ["https://gateway.example"]))
        XCTAssertFalse(trusted.findings.customEndpoint)
        let serialized = String(data: try JSONEncoder().encode(trusted.findings), encoding: .utf8)!
        XCTAssertFalse(serialized.contains("Gateway.Example"))

        let untrustedSource = #"{"env":{"ANTHROPIC_BASE_URL":"https://evil.example/?token=private"}}"#
        let untrusted = try XCTUnwrap(SelectiveSettings.inspectJSONContext(
            Data(untrustedSource.utf8), trustedEndpoints: ["https://gateway.example"]))
        XCTAssertTrue(untrusted.findings.customEndpoint)
        XCTAssertFalse(String(describing: untrusted.findings).contains("private"))

        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("settings.json")
        try Data(source.utf8).write(to: file)
        let fileInspection = try XCTUnwrap(SelectiveSettings.inspectFileContext(
            path: file.path, trustedEndpoints: ["https://gateway.example"]))
        XCTAssertFalse(fileInspection.findings.customEndpoint)
    }
    func testCATrustSettingsRetainPresenceOnlyAndUnverifiableSettingsStayMarked() throws {
        let findings = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            #"{"env":{"SSL_CERT_FILE":"/Users/private/certs/custom.pem"}}"#.utf8)))
        XCTAssertTrue(findings.customTrustConfiguration)
        XCTAssertFalse(findings.invalidTrustConfiguration)
        let serialized = String(decoding: try JSONEncoder().encode(findings), as: UTF8.self)
        XCTAssertFalse(serialized.contains("/Users/private/certs/custom.pem"))
        var incomplete = SelectiveSettings.Findings()
        incomplete.markUnverifiable()
        XCTAssertTrue(incomplete.invalidTrustConfiguration)
    }
    func testClientCertificateSettingsRetainOnlyValidityAndRejectUnverifiablePaths() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let certificate = root.appendingPathComponent("client-cert.pem")
        let key = root.appendingPathComponent("client-key.pem")
        let openssl = Process()
        openssl.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        openssl.arguments = ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
                             "-keyout", key.path, "-out", certificate.path, "-days", "1",
                             "-subj", "/CN=settings-fixture"]
        openssl.standardOutput = FileHandle.nullDevice
        openssl.standardError = FileHandle.nullDevice
        try openssl.run()
        openssl.waitUntilExit()
        XCTAssertEqual(openssl.terminationStatus, 0)

        let input: [String: Any] = ["env": ["CLAUDE_CODE_CLIENT_CERT": certificate.path,
                                            "ANTHROPIC_API_KEY": "credential-sentinel"]]
        let data = try JSONSerialization.data(withJSONObject: input)
        let findings = try XCTUnwrap(SelectiveSettings.inspectJSON(data))
        XCTAssertTrue(findings.clientCertificatesConfigured)
        XCTAssertEqual(findings.clientCertificateStatuses, [.expiring])
        XCTAssertFalse(findings.invalidClientCertificate)
        let serialized = String(decoding: try JSONEncoder().encode(findings), as: UTF8.self)
        XCTAssertFalse(serialized.contains(certificate.path))
        XCTAssertFalse(serialized.contains("BEGIN CERTIFICATE"))
        XCTAssertFalse(serialized.contains("credential-sentinel"))

        let unreadable = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            #"{"env":{"CLAUDE_CODE_CLIENT_CERT":"/private/fixture/missing.pem"}}"#.utf8)))
        XCTAssertTrue(unreadable.clientCertificatesConfigured)
        XCTAssertTrue(unreadable.invalidClientCertificate)
        XCTAssertTrue(unreadable.clientCertificateStatuses.isEmpty)
    }
    func testCapturesOnlyAutoMemoryDisableValueAndParsesBooleanSpellings() throws {
        let enabled = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            #"{"env":{"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"yes","ANTHROPIC_API_KEY":"secret"}}"#.utf8)))
        XCTAssertEqual(enabled.autoMemoryDisabled, true)
        XCTAssertFalse(String(describing: enabled).contains("secret"))
        for value in ["0", "false", "no", "off"] {
            let parsed = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
                #"{"env":{"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"\#(value)"}}"#.utf8)))
            XCTAssertEqual(parsed.autoMemoryDisabled, false, value)
        }
        let invalid = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            #"{"env":{"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"maybe"}}"#.utf8)))
        XCTAssertTrue(invalid.conflictingAutoMemorySetting)
        XCTAssertNil(invalid.autoMemoryDisabled)
        let disabled = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            #"{"autoMemoryEnabled":false,"env":{"ANTHROPIC_API_KEY":"private"}}"#.utf8)))
        XCTAssertEqual(disabled.autoMemoryDisabled, true)
        let on = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(#"{"autoMemoryEnabled":true}"#.utf8)))
        XCTAssertEqual(on.autoMemoryDisabled, false)
        let custom = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(
            #"{"autoMemoryDirectory":"/private/memory/path"}"#.utf8)))
        XCTAssertTrue(custom.customAutoMemoryDirectory)
        XCTAssertFalse(String(describing: custom).contains("/private/memory/path"))
    }
    func testCustomAutoMemoryDirectoryUsesMetadataOnlyAndStaysOutOfFindingsAndDescription() throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent(UUID().uuidString)
        let cwd = root.appendingPathComponent("project")
        let home = root.appendingPathComponent("home")
        let config = home.appendingPathComponent(".claude")
        let memory = root.appendingPathComponent("private memory")
        try FileManager.default.createDirectory(at: cwd, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: memory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: config, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let memoryPath = memory.path
        let settings = config.appendingPathComponent("settings.json")
        try Data(#"{"autoMemoryDirectory":"\#(memoryPath)"}"#.utf8).write(to: settings)
        let environment = ["HOME": home.path]

        XCTAssertEqual(SelectiveSettings.autoMemoryIndexCensus(path: memoryPath, environment: environment), true)
        XCTAssertTrue(try XCTUnwrap(SelectiveSettings.inspectFileContext(path: settings.path))
            .findings.customAutoMemoryDirectory)
        XCTAssertEqual(SelectiveSettings.inspect(environment: environment,
            workingDirectory: cwd.path).autoMemoryIndexEmpty, true)
        let secret = "memory-body-never-read-or-returned"
        try Data(secret.utf8).write(to: memory.appendingPathComponent("MEMORY.md"))
        let inspection = try XCTUnwrap(SelectiveSettings.inspectFileContext(path: settings.path))
        XCTAssertEqual(inspection.autoMemoryIndexIsEmpty(environment: environment), false)
        XCTAssertFalse(String(describing: inspection).contains(memoryPath))
        XCTAssertFalse(String(reflecting: inspection).contains(memoryPath))
        let encoded = String(data: try JSONEncoder().encode(inspection.findings), encoding: .utf8)!
        XCTAssertFalse(encoded.contains(memoryPath))
        XCTAssertFalse(encoded.contains(secret))
    }
    func testDefaultAutoMemoryCensusUsesMetadataOnlyAndRejectsSymlinkEntries() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let cwd = root.appendingPathComponent("project space")
        let home = root.appendingPathComponent("home")
        try FileManager.default.createDirectory(at: cwd, withIntermediateDirectories: true)
        let canonicalCWD = realpath(cwd.path, nil)!
        defer { free(canonicalCWD) }
        let key = String(cString: canonicalCWD).replacingOccurrences(of: #"[^A-Za-z0-9]"#,
                                                with: "-", options: .regularExpression)
        let memory = home.appendingPathComponent(".claude/projects/\(key)/memory")
        try FileManager.default.createDirectory(at: memory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let environment = ["HOME": home.path]
        XCTAssertEqual(SelectiveSettings.inspect(environment: environment,
            workingDirectory: cwd.path).autoMemoryIndexEmpty, true)
        let file = memory.appendingPathComponent("MEMORY.md")
        try Data("private-memory-content".utf8).write(to: file)
        XCTAssertEqual(SelectiveSettings.inspect(environment: environment,
            workingDirectory: cwd.path).autoMemoryIndexEmpty, false)
        try FileManager.default.removeItem(at: file)
        try FileManager.default.createSymbolicLink(atPath: memory.appendingPathComponent("link").path,
                                                   withDestinationPath: "/dev/null")
        XCTAssertNil(SelectiveSettings.inspect(environment: environment,
            workingDirectory: cwd.path).autoMemoryIndexEmpty)
    }

    func testAutoMemoryCensusHonorsExplicitProjectDirectoryNameOnlyWithConfigDirectory() throws {
        XCTAssertTrue(CurrentAssessment.environmentKeys.contains("CLAUDE_CODE_PROJECT_DIR_NAME"))
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let cwd = root.appendingPathComponent(String(repeating: "p", count: 210))
        let config = root.appendingPathComponent("config")
        let memory = config.appendingPathComponent("projects/workspace/memory")
        try FileManager.default.createDirectory(at: cwd, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: memory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }

        let environment = [
            "HOME": root.appendingPathComponent("home").path,
            "CLAUDE_CONFIG_DIR": config.path,
            "CLAUDE_CODE_PROJECT_DIR_NAME": "workspace"
        ]
        XCTAssertEqual(SelectiveSettings.inspect(environment: environment,
            workingDirectory: cwd.path).autoMemoryIndexEmpty, true)
        try Data("memory".utf8).write(to: memory.appendingPathComponent("MEMORY.md"))
        XCTAssertEqual(SelectiveSettings.inspect(environment: environment,
            workingDirectory: cwd.path).autoMemoryIndexEmpty, false)

        var invalid = environment
        invalid["CLAUDE_CODE_PROJECT_DIR_NAME"] = "../workspace"
        XCTAssertNil(SelectiveSettings.inspect(environment: invalid,
            workingDirectory: cwd.path).autoMemoryIndexEmpty)

        var withoutConfigDirectory = environment
        withoutConfigDirectory.removeValue(forKey: "CLAUDE_CONFIG_DIR")
        XCTAssertNil(SelectiveSettings.inspect(environment: withoutConfigDirectory,
            workingDirectory: cwd.path).autoMemoryIndexEmpty)
    }

    func testProjectScopedCustomAutoMemoryDirectoryStaysUnknown() throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent(UUID().uuidString)
        let cwd = root.appendingPathComponent("project")
        let settings = cwd.appendingPathComponent(".claude/settings.json")
        let memory = root.appendingPathComponent("project-chosen-memory")
        try FileManager.default.createDirectory(at: settings.deletingLastPathComponent(),
                                               withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: memory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try Data("memory".utf8).write(to: memory.appendingPathComponent("MEMORY.md"))
        let settingsObject: [String: String] = ["autoMemoryDirectory": memory.path]
        try JSONEncoder().encode(settingsObject).write(to: settings)
        defer { try? FileManager.default.removeItem(at: root) }

        let findings = SelectiveSettings.inspect(
            environment: ["HOME": root.appendingPathComponent("home").path],
            workingDirectory: cwd.path)
        XCTAssertTrue(findings.customAutoMemoryDirectory)
        XCTAssertTrue(findings.conflictingAutoMemorySetting)
        XCTAssertNil(findings.autoMemoryIndexEmpty)
    }

    func testFindingsDecodeOlderIPCWithoutNewMemoryKeys() throws {
        let data = Data(#"{"routingOverride":false,"customEndpoint":false,"tlsDisabled":false,"locale":{},"invalidLocaleKeys":[]}"#.utf8)
        let findings = try JSONDecoder().decode(SelectiveSettings.Findings.self, from: data)
        XCTAssertFalse(findings.conflictingAutoMemorySetting)
        XCTAssertNil(findings.autoMemoryIndexEmpty)
    }

    func testAuthenticationSettingsRetainMethodLabelsButNeverCredentialValues() throws {
        let source = #"""
        {"apiKeyHelper":"key-helper-command",
         "env":{"ANTHROPIC_API_KEY":"do-not-serialize-this",
                "CLAUDE_CODE_USE_BEDROCK":"true"}}
        """#
        let findings = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(source.utf8)))
        XCTAssertEqual(findings.authenticationModes, ["api-key-helper", "api-key", "bedrock"])
        let encoded = String(data: try JSONEncoder().encode(findings), encoding: .utf8)!
        XCTAssertFalse(encoded.contains("do-not-serialize-this"))
        XCTAssertFalse(encoded.contains("key-helper-command"))
    }
    func testModelSettingsRetainOnlyBoundedModelIdentifiers() throws {
        let findings = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(#"""
        {"model":"claude-opus-4-8",
         "env":{"ANTHROPIC_MODEL":"claude-sonnet-4-5-20250929",
                "ANTHROPIC_DEFAULT_MODEL":"sonnet",
                "ANTHROPIC_BASE_URL":"https://private-endpoint.invalid"}}
        """#.utf8)))
        XCTAssertEqual(findings.modelIdentifiers,
                       ["claude-opus-4-8", "claude-sonnet-4-5-20250929", "sonnet"])
        let encoded = String(data: try JSONEncoder().encode(findings), encoding: .utf8)!
        XCTAssertFalse(encoded.contains("private-endpoint"))
        let malformed = try XCTUnwrap(SelectiveSettings.inspectJSON(Data(#"{"model":"model with spaces"}"#.utf8)))
        XCTAssertTrue(malformed.invalidModelIdentifier)
        XCTAssertTrue(malformed.modelIdentifiers.isEmpty)
    }

    func testModelEnvironmentCollectorDoesNotRetainMalformedValues() {
        let valid = SelectiveSettings.modelEnvironment(["ANTHROPIC_MODEL": "claude-opus-4-8"])
        XCTAssertEqual(valid.modelIdentifiers, ["claude-opus-4-8"])
        let invalid = SelectiveSettings.modelEnvironment(["ANTHROPIC_MODEL": "secret value"])
        XCTAssertTrue(invalid.invalidModelIdentifier)
        XCTAssertTrue(invalid.modelIdentifiers.isEmpty)
        XCTAssertFalse(String(describing: invalid).contains("secret value"))
    }
    func testSkipsUnrelatedKeysAndRejectsMalformedOrNonRegularFiles() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("settings.json")
        try Data(#"{"env":{"ANTHROPIC_API_KEY":"secret"},"other":{"https_proxy":"ignored"}}"#.utf8).write(to: file)
        let clean = try XCTUnwrap(SelectiveSettings.inspectFile(path: file.path))
        XCTAssertFalse(clean.routingOverride)
        try Data(#"{"env":{"https_proxy":"x"}"#.utf8).write(to: file)
        XCTAssertNil(SelectiveSettings.inspectFile(path: file.path))
        let fifo = root.appendingPathComponent("pipe").path
        XCTAssertEqual(mkfifo(fifo, 0o600), 0)
        XCTAssertNil(SelectiveSettings.inspectFile(path: fifo))
        let inspection = SelectiveSettings.inspect(environment: [:], workingDirectory: nil,
                                                   additionalSettingsPath: fifo)
        XCTAssertTrue(inspection.routingOverride)
        XCTAssertTrue(inspection.customEndpoint)
        XCTAssertTrue(inspection.tlsDisabled)
        XCTAssertEqual(inspection.invalidLocaleKeys.count, 5)
    }
    func testMergesUserAndProjectConfiguration() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let user = root.appendingPathComponent("user")
        let project = root.appendingPathComponent("project/.claude")
        try FileManager.default.createDirectory(at: user, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        try Data(#"{"env":{"ANTHROPIC_BASE_URL":"fixture"}}"#.utf8).write(to: user.appendingPathComponent("settings.json"))
        try Data(#"{"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"0","TZ":"Asia/Tokyo","LANG":"ja_JP.UTF-8"}}"#.utf8)
            .write(to: project.appendingPathComponent("settings.local.json"))
        let result = SelectiveSettings.inspect(environment: ["CLAUDE_CONFIG_DIR": user.path],
                                               workingDirectory: project.deletingLastPathComponent().path)
        XCTAssertTrue(result.customEndpoint)
        XCTAssertTrue(result.tlsDisabled)
        XCTAssertTrue(result.routingOverride)
        XCTAssertEqual(result.locale["TZ"], "Asia/Tokyo")
        XCTAssertEqual(result.locale["LANG"], "ja_JP.UTF-8")
    }

    func testSettingsRoutingContextContainsOnlyProxyVariablesAndFailsClosedOnScopeConflict() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let user = root.appendingPathComponent("user")
        let project = root.appendingPathComponent("project/.claude")
        try FileManager.default.createDirectory(at: user, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        try Data(#"{"env":{"https_proxy":"http://user:secret@127.0.0.1:8000","ANTHROPIC_API_KEY":"never-retain"}}"#.utf8)
            .write(to: user.appendingPathComponent("settings.json"))
        try Data(#"{"env":{"https_proxy":"http://127.0.0.1:9000"}}"#.utf8)
            .write(to: project.appendingPathComponent("settings.local.json"))
        let result = SelectiveSettings.inspectContext(
            environment: ["CLAUDE_CONFIG_DIR": user.path],
            workingDirectory: project.deletingLastPathComponent().path)
        XCTAssertTrue(result.routingConflict)
        XCTAssertNotNil(result.routingEnvironment["https_proxy"])
        let encoded = try JSONEncoder().encode(result.findings)
        let serialized = String(decoding: encoded, as: UTF8.self)
        XCTAssertFalse(serialized.contains("secret"))
        XCTAssertFalse(serialized.contains("never-retain"))
    }

    func testManagedDropInDirectoryEnumeratesSortedJSONFilesAndRejectsSymlinks() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        try Data(#"{"env":{"TZ":"UTC"}}"#.utf8).write(to: root.appendingPathComponent("20-locale.json"))
        try Data("ignored".utf8).write(to: root.appendingPathComponent("README.txt"))
        let files = try XCTUnwrap(SelectiveSettings.managedSettingsFiles(in: root.path))
        XCTAssertEqual(files.map { URL(fileURLWithPath: $0).lastPathComponent }, ["20-locale.json"])
        try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("30-unsafe.json").path,
                                                   withDestinationPath: "/dev/null")
        XCTAssertNil(SelectiveSettings.managedSettingsFiles(in: root.path))
    }
}
