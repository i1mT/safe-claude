import Darwin
import Foundation

public enum ClaudeTraceTarget: String, CaseIterable, Sendable {
    case claudeAI = "claude.ai"
    case claudeCom = "claude.com"
    case api = "api.anthropic.com"
    case platform = "platform.claude.com"
}

public enum IPFamily: String, Sendable {
    case automatic, ipv4, ipv6
}

/// Contains a sensitive observed IP address; callers must not log the value.
public struct TraceObservation: Equatable, Sendable {
    public let targetHost: String
    public let ip: String
    public let countryCode: String?
    public let clock: HTTPClockSample?
    public init(targetHost: String, ip: String, countryCode: String?, clock: HTTPClockSample? = nil) {
        self.targetHost = targetHost; self.ip = ip; self.countryCode = countryCode; self.clock = clock
    }
}

public enum TraceProbeResult: Equatable, Sendable {
    case observed(TraceObservation)
    case unknown(reason: String)
}

/// An isolated, unauthenticated route observation. Callers must still verify
/// Claude's settings scopes, trust configuration and actual target context.
public enum TraceProbe {
    public static func observe(
        _ target: ClaudeTraceTarget,
        environment: [String: String],
        settingsEnvironment: [String: String] = [:],
        family: IPFamily = .automatic
    ) -> TraceProbeResult {
        let url = URL(string: "https://\(target.rawValue)/cdn-cgi/trace")!
        return execute(url: url, environment: environment, settingsEnvironment: settingsEnvironment,
                       family: family, executable: URL(fileURLWithPath: "/usr/bin/curl"))
    }

    // Internal executable injection makes failure, timeout and environment
    // isolation testable without making arbitrary commands a public interface.
    static func execute(
        url: URL,
        environment: [String: String],
        settingsEnvironment: [String: String] = [:],
        family: IPFamily = .automatic,
        executable: URL
    ) -> TraceProbeResult {
        guard url.scheme == "https", let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil else {
            return .unknown(reason: "INVALID_TRACE_TARGET")
        }
        guard SystemProxyState.current() == .inactive else {
            return .unknown(reason: "SYSTEM_PROXY_UNVERIFIED")
        }
        let targetPort = url.port ?? 443
        let route = ProxyConfiguration.resolve(
            targetHost: host, targetPort: targetPort, environment: environment,
            settingsEnvironment: settingsEnvironment
        )

        // Curl and Claude do not necessarily apply custom trust, client keys,
        // or explicit certificate store settings identically.
        for key in ["NODE_EXTRA_CA_CERTS", "CLAUDE_CODE_CERT_STORE", "CLAUDE_CODE_CLIENT_CERT",
                    "CLAUDE_CODE_CLIENT_KEY", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE",
                    "SSL_CERT_DIR", "NODE_USE_SYSTEM_CA"] {
            if [environment[key], settingsEnvironment[key]].contains(where: { !($0 ?? "").isEmpty }) {
                return .unknown(reason: "CUSTOM_TLS_CONFIGURATION")
            }
        }

        var childEnvironment = ["PATH": "/usr/bin:/bin", "LANG": "C"]
        let targetCertificateFailureUnambiguous: Bool
        switch route {
        case .unknown(let reason):
            return .unknown(reason: reason)
        case .direct:
            targetCertificateFailureUnambiguous = true
        case .proxy(let proxy):
            // A TLS proxy has its own certificate, so curl's code 60 alone
            // cannot identify which certificate failed.
            targetCertificateFailureUnambiguous = proxy.scheme == "http"
            guard family == .automatic else { return .unknown(reason: "PROXY_TARGET_FAMILY_UNCONTROLLED") }
            let raw: String?
            if proxy.source == "environment" {
                raw = environment[proxy.sourceKey]
            } else {
                raw = settingsEnvironment[proxy.sourceKey]
            }
            guard let raw, !raw.isEmpty else { return .unknown(reason: "PROXY_VALUE_UNAVAILABLE") }
            // This variable reaches only the local curl process. In particular,
            // it never appears in argv, logs or the returned observation.
            childEnvironment["https_proxy"] = raw
        }

        let child = Process()
        child.executableURL = executable
        // A missing address family often takes the entire network timeout.
        // Bound supplemental family probes below the launch decision budget;
        // timing out remains unknown rather than evidence of absence.
        let probeTimeout = family == .automatic ? 2.0 : 1.0
        var arguments = ["-q", "--silent", "--show-error", "--fail", "--max-time", String(probeTimeout),
                         "--max-filesize", "8192", "--proto", "=https",
                         "--header", "Cache-Control: no-store",
                         "--write-out", "\n__SAFE_STATUS__=%{http_code}\n__SAFE_DATE__=%header{date}\n__SAFE_AGE__=%header{age}\n"]
        switch family {
        case .automatic: break
        case .ipv4: arguments.append("-4")
        case .ipv6: arguments.append("-6")
        }
        arguments.append(contentsOf: ["--url", url.absoluteString])
        child.arguments = arguments
        child.environment = childEnvironment
        child.standardInput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        let output = Pipe()
        child.standardOutput = output
        let startWall = Date()
        let startUptime = ProcessInfo.processInfo.systemUptime
        do {
            try child.run()
        } catch {
            return .unknown(reason: "TRACE_LAUNCH_FAILED")
        }
        let fd = output.fileHandleForReading.fileDescriptor
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        let deadline = ProcessInfo.processInfo.systemUptime + probeTimeout + 0.4
        var data = Data()
        var reachedEOF = false
        var buffer = [UInt8](repeating: 0, count: 4096)
        while ProcessInfo.processInfo.systemUptime < deadline {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count > 0 {
                data.append(contentsOf: buffer.prefix(count))
                if data.count > 8192 { break }
            } else if count == 0 {
                reachedEOF = true
                if !child.isRunning { break }
            } else if errno != EAGAIN && errno != EINTR {
                break
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        if child.isRunning {
            child.terminate()
            let killDeadline = ProcessInfo.processInfo.systemUptime + 0.1
            while child.isRunning && ProcessInfo.processInfo.systemUptime < killDeadline {
                Thread.sleep(forTimeInterval: 0.01)
            }
            if child.isRunning { _ = Darwin.kill(child.processIdentifier, SIGKILL) }
            child.waitUntilExit()
            return .unknown(reason: "TRACE_TIMEOUT")
        }
        child.waitUntilExit()
        guard reachedEOF else { return .unknown(reason: data.count > 8192 ? "INVALID_TRACE_RESPONSE" : "TRACE_TIMEOUT") }
        guard child.terminationReason == .exit, child.terminationStatus == 0 else {
            if child.terminationReason == .exit && child.terminationStatus == 60 &&
                targetCertificateFailureUnambiguous {
                return .unknown(reason: "CERTIFICATE_VERIFICATION_FAILED")
            }
            return .unknown(reason: "TRACE_REQUEST_FAILED")
        }
        guard data.count <= 8192, let text = String(data: data, encoding: .utf8) else {
            return .unknown(reason: "INVALID_TRACE_RESPONSE")
        }
        let endWall = Date()
        let elapsed = ProcessInfo.processInfo.systemUptime - startUptime
        var lines = text.split(whereSeparator: \.isNewline)
        var clock: HTTPClockSample?
        if let age = lines.last, age.hasPrefix("__SAFE_AGE__=") {
            lines.removeLast()
            if let date = lines.last, date.hasPrefix("__SAFE_DATE__=") {
                lines.removeLast()
                let rawAge = String(age.dropFirst("__SAFE_AGE__=".count))
                if rawAge.isEmpty || rawAge == "0" {
                    clock = HTTPClockSample.parse(String(date.dropFirst("__SAFE_DATE__=".count)),
                                                  start: startWall, end: endWall, elapsed: elapsed)
                }
            }
        }
        guard lines.popLast() == "__SAFE_STATUS__=200" else {
            return .unknown(reason: "TRACE_HTTP_STATUS")
        }
        let result = parse(lines.joined(separator: "\n"), targetHost: host)
        if case .observed(let observation) = result, let bytes = IPAddress.bytes(observation.ip) {
            if family == .ipv4 && bytes.first != 4 || family == .ipv6 && bytes.first != 6 {
                return .unknown(reason: "TRACE_FAMILY_MISMATCH")
            }
        }
        if case .observed(let observation) = result {
            return .observed(TraceObservation(targetHost: observation.targetHost, ip: observation.ip,
                                               countryCode: observation.countryCode, clock: clock))
        }
        return result
    }

    static func parse(_ text: String, targetHost: String) -> TraceProbeResult {
        var values: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            guard let separator = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<separator])
            let value = String(line[line.index(after: separator)...])
            guard values[key] == nil else { return .unknown(reason: "DUPLICATE_TRACE_FIELD") }
            values[key] = value
        }
        guard let ip = values["ip"], IPAddress.bytes(ip) != nil else {
            return .unknown(reason: "TRACE_IP_UNAVAILABLE")
        }
        let country = values["loc"]?.uppercased()
        let validCountry = country.flatMap {
            $0.utf8.count == 2 && $0.utf8.allSatisfy { (65...90).contains($0) } ? $0 : nil
        }
        return .observed(TraceObservation(targetHost: targetHost, ip: ip, countryCode: validCountry))
    }
}
