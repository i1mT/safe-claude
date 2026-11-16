import Darwin
import Foundation

/// Restricted HTTPS GET for the geolocation adapter. Proxy credentials remain
/// in the child environment and never enter arguments, observations or logs.
enum GeolocationTransport {
    static func get(url: URL, environment: [String: String], settings: [String: String] = [:],
                    executable: URL = URL(fileURLWithPath: "/usr/bin/curl"),
                    systemProxy: SystemProxyState = .current()) throws -> Data {
        try execute(url: url, body: nil, environment: environment, settings: settings,
                    executable: executable, systemProxy: systemProxy)
    }

    static func post(url: URL, body: Data, environment: [String: String], settings: [String: String] = [:],
                     executable: URL = URL(fileURLWithPath: "/usr/bin/curl"),
                     systemProxy: SystemProxyState = .current()) throws -> Data {
        try execute(url: url, body: body, environment: environment, settings: settings,
                    executable: executable, systemProxy: systemProxy)
    }

    private static func execute(url: URL, body: Data?, environment: [String: String],
                                settings: [String: String], executable: URL,
                                systemProxy: SystemProxyState) throws -> Data {
        var configFile: URL?
        defer {
            if let configFile { unlink(configFile.path) }
        }
        guard url.scheme == "https", let host = url.host, url.port == nil,
              url.user == nil, url.password == nil, url.fragment == nil else {
            throw ReputationError.requestFailed
        }
        switch host {
        case "ipwho.is":
            guard body == nil, url.query == nil, IPAddress.bytes(url.lastPathComponent) != nil,
                  url.path == "/" + url.lastPathComponent else { throw ReputationError.requestFailed }
        case "proxycheck.io":
            let prefix = "tag=0&risk=2&days=30&ver=24-June-2026"
            let query = url.query ?? ""
            let key = query.hasPrefix(prefix + "&key=") ? String(query.dropFirst((prefix + "&key=").count)) : nil
            let validKey = key.map { !$0.isEmpty && $0.utf8.count <= 128 && $0.utf8.allSatisfy {
                (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45
            }} ?? false
            guard body == nil, url.path == "/v3/" + url.lastPathComponent,
                  query == prefix || validKey else { throw ReputationError.requestFailed }
        case "api.ipapi.is":
            guard url.path == "/", url.query == nil,
                  let body, (1...4096).contains(body.count),
                  let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                  Set(object.keys) == Set(["ips", "key"]),
                  let key = object["key"] as? String,
                  (1...256).contains(key.utf8.count),
                  key.utf8.allSatisfy({ (33...126).contains($0) }),
                  let ips = object["ips"] as? [String], ips.count == 1,
                  IPAddress.bytes(ips[0]) != nil else { throw ReputationError.requestFailed }
        default: throw ReputationError.requestFailed
        }
        guard systemProxy == .inactive else { throw ReputationError.routeUnverified }
        let tlsKeys = ["NODE_EXTRA_CA_CERTS", "CLAUDE_CODE_CERT_STORE", "CLAUDE_CODE_CLIENT_CERT",
                       "CLAUDE_CODE_CLIENT_KEY", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE",
                       "SSL_CERT_DIR", "NODE_USE_SYSTEM_CA"]
        guard !tlsKeys.contains(where: { !(environment[$0] ?? "").isEmpty || !(settings[$0] ?? "").isEmpty }) else {
            throw ReputationError.routeUnverified
        }
        let route = ProxyConfiguration.resolve(targetHost: host, environment: environment,
                                               settingsEnvironment: settings)
        var childEnvironment = ["PATH": "/usr/bin:/bin", "LANG": "C"]
        switch route {
        case .unknown:
            throw ReputationError.routeUnverified
        case .direct:
            break
        case .proxy(let proxy):
            let raw = proxy.source == "settings" ? settings[proxy.sourceKey] : environment[proxy.sourceKey]
            guard let raw, !raw.isEmpty else { throw ReputationError.routeUnverified }
            childEnvironment["https_proxy"] = raw
        }
        let process = Process()
        process.executableURL = executable
        var arguments = ["-q", "--silent", "--show-error", "--fail", "--max-time", "2",
                         "--max-filesize", "65536", "--proto", "=https", "--header", "Cache-Control: no-store",
                         "--write-out", "\n__SAFE_STATUS__=%{http_code}\n"]
        if body != nil {
            let configURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("safeclaude-curl-\(UUID().uuidString).conf")
            let config = Data("url = \"\(url.absoluteString)\"\nrequest = \"POST\"\nheader = \"Content-Type: application/json\"\n".utf8)
            let configFD = open(configURL.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard configFD >= 0 else { throw ReputationError.requestFailed }
            defer { close(configFD) }
            try writeAll(config, to: configFD)
            guard fsync(configFD) == 0 else { throw ReputationError.requestFailed }
            configFile = configURL
            arguments.append(contentsOf: ["--config", configURL.path, "--data-binary", "@-"])
        } else {
            arguments.append(contentsOf: ["--config", "-"])
        }
        process.arguments = arguments
        process.environment = childEnvironment
        let input = Pipe()
        process.standardInput = input
        let inputData = body ?? Data("url = \"\(url.absoluteString)\"\n".utf8)
        input.fileHandleForWriting.write(inputData)
        try? input.fileHandleForWriting.close()
        process.standardError = FileHandle.nullDevice
        let output = Pipe()
        process.standardOutput = output
        do { try process.run() } catch { throw ReputationError.requestFailed }
        let fd = output.fileHandleForReading.fileDescriptor
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        let deadline = ProcessInfo.processInfo.systemUptime + 2.4
        var bytes = Data()
        var eof = false
        var chunk = [UInt8](repeating: 0, count: 4096)
        while ProcessInfo.processInfo.systemUptime < deadline {
            let count = Darwin.read(fd, &chunk, chunk.count)
            if count > 0 {
                bytes.append(contentsOf: chunk.prefix(count))
                if bytes.count > 65_536 { break }
            } else if count == 0 {
                eof = true
                if !process.isRunning { break }
            } else if errno != EAGAIN && errno != EINTR {
                break
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        if process.isRunning {
            process.terminate()
            let killDeadline = ProcessInfo.processInfo.systemUptime + 0.1
            while process.isRunning && ProcessInfo.processInfo.systemUptime < killDeadline {
                Thread.sleep(forTimeInterval: 0.01)
            }
            if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            throw ReputationError.requestFailed
        }
        process.waitUntilExit()
        guard eof, process.terminationReason == .exit, process.terminationStatus == 0,
              bytes.count <= 65_536, let text = String(data: bytes, encoding: .utf8) else {
            throw ReputationError.requestFailed
        }
        let marker = "\n__SAFE_STATUS__=200\n"
        guard text.hasSuffix(marker) else { throw ReputationError.requestFailed }
        return Data(text.dropLast(marker.count).utf8)
    }

    private static func writeAll(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw ReputationError.requestFailed }
                offset += count
            }
        }
    }
}
