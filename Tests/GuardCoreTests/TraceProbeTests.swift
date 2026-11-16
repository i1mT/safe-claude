import Foundation
import XCTest
@testable import GuardCore

final class TraceProbeTests: XCTestCase {
    func testHTTPSClockHeaderAndCacheAgeAreBoundToSuccessfulTrace() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent("fake-curl")
        func probe(age: String) throws -> TraceProbeResult {
            let script = "#!/bin/sh\nprintf 'ip=192.0.2.1\\n__SAFE_STATUS__=200\\n__SAFE_DATE__=Fri, 13 Nov 2026 04:28:20 GMT\\n__SAFE_AGE__=\(age)\\n'\n"
            try Data(script.utf8).write(to: executable)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
            return TraceProbe.execute(url: URL(string: "https://api.anthropic.com/cdn-cgi/trace")!,
                                      environment: [:], executable: executable)
        }
        guard case .observed(let fresh) = try probe(age: "0") else { return XCTFail("missing trace") }
        XCTAssertNotNil(fresh.clock)
        guard case .observed(let cached) = try probe(age: "60") else { return XCTFail("missing trace") }
        XCTAssertNil(cached.clock)
    }
    func testCertificateFailureIsNotAttributedToTargetThroughTLSProxy() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent("fake-curl")
        try Data("#!/bin/sh\nexit 60\n".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let url = URL(string: "https://api.anthropic.com/cdn-cgi/trace")!
        XCTAssertEqual(TraceProbe.execute(url: url, environment: [:], executable: executable),
                       .unknown(reason: "CERTIFICATE_VERIFICATION_FAILED"))
        XCTAssertEqual(TraceProbe.execute(url: url, environment: ["HTTPS_PROXY": "https://127.0.0.1:8080"],
                                          executable: executable),
                       .unknown(reason: "TRACE_REQUEST_FAILED"))
    }
    func testTraceParsesOnlyValidAddressAndCountry() {
        XCTAssertEqual(TraceProbe.parse("ip=192.0.2.1\nloc=us\n", targetHost: "api.anthropic.com"),
                       .observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1",
                                                  countryCode: "US")))
        XCTAssertEqual(TraceProbe.parse("ip=2001:db8::1\nloc=U$S\n", targetHost: "fixture"),
                       .observed(TraceObservation(targetHost: "fixture", ip: "2001:db8::1", countryCode: nil)))
        XCTAssertEqual(TraceProbe.parse("ip=bad\nloc=US\n", targetHost: "fixture"),
                       .unknown(reason: "TRACE_IP_UNAVAILABLE"))
        XCTAssertEqual(TraceProbe.parse("ip=192.0.2.1\nip=192.0.2.2\n", targetHost: "fixture"),
                       .unknown(reason: "DUPLICATE_TRACE_FIELD"))
    }

    func testCredentialsStayOutOfArgvAndUnrelatedEnvironment() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("fake-curl")
        let script = """
        #!/bin/sh
        [ "$1" = "-q" ] || exit 20
        [ -z "${ANTHROPIC_API_KEY+x}" ] || exit 21
        [ "$https_proxy" = "http://fixture-user:fixture-pass@127.0.0.1:8123" ] || exit 22
        case "$*" in *fixture-pass*|*fixture-user*) exit 23;; esac
        printf 'ip=192.0.2.1\\nloc=US\\n__SAFE_STATUS__=200\\n'
        """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let result = TraceProbe.execute(
            url: URL(string: "https://api.anthropic.com/cdn-cgi/trace")!,
            environment: [
                "ANTHROPIC_API_KEY": "must-not-be-inherited",
                "HTTPS_PROXY": "http://fixture-user:fixture-pass@127.0.0.1:8123",
            ], executable: executable
        )
        XCTAssertEqual(result, .observed(TraceObservation(targetHost: "api.anthropic.com",
                                                           ip: "192.0.2.1", countryCode: "US")))
    }

    func testUncertainRoutingAndCustomTLSStopBeforeLaunch() {
        let url = URL(string: "https://api.anthropic.com/cdn-cgi/trace")!
        let missing = URL(fileURLWithPath: "/nonexistent")
        XCTAssertEqual(TraceProbe.execute(url: url, environment: ["ALL_PROXY": "socks5://127.0.0.1:1"],
                                          executable: missing), .unknown(reason: "ALL_PROXY_UNVERIFIED"))
        XCTAssertEqual(TraceProbe.execute(url: url, environment: ["NODE_EXTRA_CA_CERTS": "/tmp/ca.pem"],
                                          executable: missing), .unknown(reason: "CUSTOM_TLS_CONFIGURATION"))
        XCTAssertEqual(TraceProbe.execute(url: url, environment: [:], executable: missing),
                       .unknown(reason: "TRACE_LAUNCH_FAILED"))
    }

    func testConflictingTLSAndProxyFamilyFailClosed() {
        let url = URL(string: "https://api.anthropic.com/cdn-cgi/trace")!
        let missing = URL(fileURLWithPath: "/nonexistent")
        XCTAssertEqual(TraceProbe.execute(url: url, environment: ["NODE_EXTRA_CA_CERTS": ""],
                                          settingsEnvironment: ["NODE_EXTRA_CA_CERTS": "/tmp/ca"], executable: missing),
                       .unknown(reason: "CUSTOM_TLS_CONFIGURATION"))
        XCTAssertEqual(TraceProbe.execute(url: url, environment: ["HTTPS_PROXY": "http://127.0.0.1:8123"],
                                          family: .ipv4, executable: missing),
                       .unknown(reason: "PROXY_TARGET_FAMILY_UNCONTROLLED"))
    }

    func testInheritedPipeDoesNotDefeatDeadline() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("fake-curl")
        try Data("#!/bin/sh\nsleep 4 &\nexit 0\n".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let start = ProcessInfo.processInfo.systemUptime
        XCTAssertEqual(TraceProbe.execute(url: URL(string: "https://api.anthropic.com/cdn-cgi/trace")!,
                                          environment: [:], executable: executable), .unknown(reason: "TRACE_TIMEOUT"))
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start, 3.5)
    }

    func testDirectObservedAddressMatchesRequestedFamily() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("fake-curl")
        try Data("#!/bin/sh\nprintf 'ip=192.0.2.1\\n__SAFE_STATUS__=200\\n'\n".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let url = URL(string: "https://api.anthropic.com/cdn-cgi/trace")!
        XCTAssertEqual(TraceProbe.execute(url: url, environment: [:], family: .ipv4, executable: executable),
                       .observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: nil)))
        XCTAssertEqual(TraceProbe.execute(url: url, environment: [:], family: .ipv6, executable: executable),
                       .unknown(reason: "TRACE_FAMILY_MISMATCH"))
    }

    func testUnsupportedTargetIsNotFetched() {
        let result = TraceProbe.execute(url: URL(string: "http://example.com/")!,
                                        environment: [:], executable: URL(fileURLWithPath: "/usr/bin/curl"))
        XCTAssertEqual(result, .unknown(reason: "INVALID_TRACE_TARGET"))
    }

    func testRedirectResponseIsNotAcceptedAsTrace() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("fake-curl")
        try Data("#!/bin/sh\nprintf 'ip=192.0.2.1\\n__SAFE_STATUS__=302\\n'\n".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let result = TraceProbe.execute(url: URL(string: "https://api.anthropic.com/cdn-cgi/trace")!,
                                        environment: [:], executable: executable)
        XCTAssertEqual(result, .unknown(reason: "TRACE_HTTP_STATUS"))
    }
}
