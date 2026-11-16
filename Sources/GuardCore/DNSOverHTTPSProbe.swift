import Foundation
import Network
import Security

/// One bounded RFC 8484 diagnostic request to an explicitly configured DoH
/// endpoint. The DNS server IP and TLS name come from the active DNS profile;
/// neither is persisted by this adapter.
public enum DNSOverHTTPSProbe {
    fileprivate static let maximumHTTPResponseBytes = 8_192

    public static func observe(serverURL: URL, serverIP: String,
                               timeout: TimeInterval = 2.5) -> String? {
        guard (0.1...3).contains(timeout),
              IPAddress.bytes(serverIP) != nil,
              serverURL.scheme?.lowercased() == "https",
              let host = serverURL.host, validHost(host),
              serverURL.user == nil, serverURL.password == nil,
              serverURL.fragment == nil,
              (1...65_535).contains(serverURL.port ?? 443),
              let components = URLComponents(url: serverURL, resolvingAgainstBaseURL: false),
              components.percentEncodedPath.utf8.count <= 1_024,
              (components.percentEncodedQuery?.utf8.count ?? 0) <= 1_024 else { return nil }

        let transactionID = UInt16.random(in: .min ... .max)
        guard let query = DNSResolverEgressProbe.diagnosticQuery(transactionID: transactionID),
              let port = NWEndpoint.Port(rawValue: UInt16(serverURL.port ?? 443)) else { return nil }
        let path = (components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath) +
            (components.percentEncodedQuery.map { "?" + $0 } ?? "")
        let requestHost = serverURL.port.map { "\(host):\($0)" } ?? host
        var request = Data("POST \(path) HTTP/1.1\r\nHost: \(requestHost)\r\n".utf8)
        request.append(Data("Accept: application/dns-message\r\nContent-Type: application/dns-message\r\n".utf8))
        request.append(Data("Cache-Control: no-store\r\nConnection: close\r\nContent-Length: \(query.count)\r\n\r\n".utf8))
        request.append(query)
        let exchange = DNSOverHTTPSExchange(serverIP: serverIP, host: host, port: port,
            request: request, transactionID: transactionID, timeout: timeout)
        return exchange.run()
    }

    /// Strictly accepts one bounded HTTP 200 DNS-message response with an exact
    /// Content-Length. Chunked and ambiguous response framing remain unknown.
    public static func parseHTTPResponse(_ data: Data, transactionID: UInt16) -> String? {
        guard data.count <= maximumHTTPResponseBytes,
              let separator = data.range(of: Data("\r\n\r\n".utf8)),
              separator.lowerBound <= 4_096,
              let header = String(data: data[..<separator.lowerBound], encoding: .ascii) else { return nil }
        let lines = header.components(separatedBy: "\r\n")
        let status = lines.first?.split(separator: " ", maxSplits: 2)
        guard let status, status.count >= 2,
              status[0] == "HTTP/1.1" || status[0] == "HTTP/1.0",
              status[1] == "200", lines.count <= 64 else { return nil }
        var contentLength: Int?
        var contentType: String?
        var sawTransferEncoding = false
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch name {
            case "content-length":
                guard contentLength == nil, let parsed = Int(value),
                      (12...4_096).contains(parsed) else { return nil }
                contentLength = parsed
            case "content-type":
                guard contentType == nil else { return nil }
                contentType = value.split(separator: ";", maxSplits: 1)
                    .first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            case "transfer-encoding":
                sawTransferEncoding = true
            default:
                break
            }
        }
        let bodyStart = separator.upperBound
        guard !sawTransferEncoding, contentType == "application/dns-message",
              let contentLength, data.count - bodyStart == contentLength else { return nil }
        return DNSResolverEgressProbe.parseResponse(Data(data[bodyStart...]),
                                                     transactionID: transactionID)
    }

    private static func validHost(_ value: String) -> Bool {
        let normalized = value.hasSuffix(".") ? String(value.dropLast()) : value
        return normalized.utf8.count <= 253 && !normalized.isEmpty &&
            normalized.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
                !label.isEmpty && label.utf8.count <= 63 &&
                label.first != "-" && label.last != "-" &&
                label.utf8.allSatisfy {
                    (97...122).contains($0) || (65...90).contains($0) ||
                    (48...57).contains($0) || $0 == 45
                }
            }
    }
}

enum DNSOverHTTPSTrust {
    static func evaluate(_ trust: SecTrust, serverName: String) -> Bool {
        let policy = SecPolicyCreateSSL(true, serverName as CFString)
        guard SecTrustSetPolicies(trust, policy) == errSecSuccess else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }
}

private final class DNSOverHTTPSExchange: @unchecked Sendable {
    private let connection: NWConnection
    private let request: Data
    private let transactionID: UInt16
    private let timeout: TimeInterval
    private let queue = DispatchQueue(label: "com.safeclaude.dns-doh-probe")
    private let completed = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var started = false
    private var finished = false
    private var response = Data()
    private var result: String?

    init(serverIP: String, host: String, port: NWEndpoint.Port,
         request: Data, transactionID: UInt16, timeout: TimeInterval) {
        self.request = request
        self.transactionID = transactionID
        self.timeout = timeout
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        host.withCString { sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, $0) }
        // The TCP connection is pinned to the resolver IP, while its certificate
        // must identify the hostname from the configured DoH URL. Preserve system
        // trust evaluation and apply the hostname explicitly instead of comparing
        // the certificate to the IP endpoint.
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, completion in
            let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            completion(DNSOverHTTPSTrust.evaluate(secTrust, serverName: host))
        }, queue)
        connection = NWConnection(host: NWEndpoint.Host(serverIP), port: port,
                                  using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()))
    }

    func run() -> String? {
        connection.stateUpdateHandler = { [weak self] state in self?.update(state) }
        connection.start(queue: queue)
        _ = completed.wait(timeout: .now() + timeout)
        connection.cancel()
        lock.lock()
        defer { lock.unlock() }
        return result
    }

    private func update(_ state: NWConnection.State) {
        switch state {
        case .ready:
            lock.lock()
            let send = !started && !finished
            started = true
            lock.unlock()
            if send {
                connection.send(content: request, completion: .contentProcessed { [weak self] error in
                    guard let self else { return }
                    if error != nil { self.finish(nil) } else { self.receive() }
                })
            }
        case .failed, .cancelled:
            finish(nil)
        default:
            break
        }
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8_192) { [weak self] data, _, complete, error in
            guard let self else { return }
            if error != nil {
                self.finish(nil)
                return
            }
            self.lock.lock()
            guard !self.finished else {
                self.lock.unlock()
                return
            }
            if let data { self.response.append(data) }
            let tooLarge = self.response.count > DNSOverHTTPSProbe.maximumHTTPResponseBytes
            let parsed = tooLarge ? nil : DNSOverHTTPSProbe.parseHTTPResponse(
                self.response, transactionID: self.transactionID)
            let hasCompleteResponse = parsed != nil
            self.lock.unlock()
            if tooLarge || hasCompleteResponse || complete {
                self.finish(parsed)
            } else {
                self.receive()
            }
        }
    }

    private func finish(_ address: String?) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        result = address
        lock.unlock()
        completed.signal()
    }
}
