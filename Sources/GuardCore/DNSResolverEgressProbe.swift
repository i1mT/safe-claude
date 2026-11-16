import Darwin
import Foundation
import Network

/// Queries a resolver's recursive egress using Akamai's public DNS TXT
/// diagnostic. Only the returned public egress IP leaves process memory.
public enum DNSResolverEgressProbe {
    public static let queryName = "whoami.ds.akahelp.net"
    private static let maximumResponseBytes = 4_096

    /// This probe sends a bare UDP DNS packet. Encrypted DNS ports such as
    /// DoT/DoH must use their configured transport and cannot be probed this way.
    public static func supportsDirectUDP(_ endpoint: DNSResolverEndpoint) -> Bool {
        endpoint.port == 53 && IPAddress.bytes(endpoint.host) != nil
    }

    /// DNS-over-TLS is attempted only on its registered port. Network.framework
    /// performs normal system trust evaluation for the configured address;
    /// certificate errors remain unknown and are never bypassed.
    public static func supportsDNSOverTLS(_ endpoint: DNSResolverEndpoint) -> Bool {
        endpoint.port == 853 && (IPAddress.bytes(endpoint.host) != nil ||
            DNSPathEvidence.resolverIdentity(host: endpoint.host, port: endpoint.port) != nil)
    }

    public static func parseStreamFrame(_ data: Data, transactionID: UInt16) -> String? {
        guard data.count >= 14, data.count <= maximumResponseBytes + 2,
              let length = data.prefix(2).withUnsafeBytes({ bytes -> Int? in
                  guard bytes.count == 2 else { return nil }
                  return Int(bytes[0]) << 8 | Int(bytes[1])
              }),
              length >= 12, length == data.count - 2 else { return nil }
        return parseResponse(Data(data.dropFirst(2)), transactionID: transactionID)
    }

    public static func diagnosticQuery(transactionID: UInt16) -> Data? {
        makeQuery(transactionID: transactionID)
    }

    public static func parseResponse(_ data: Data, transactionID: UInt16) -> String? {
        var reader = DNSResponseReader(data)
        guard let id = reader.readUInt16(), id == transactionID,
              let flags = reader.readUInt16(), flags & 0x8000 != 0,
              flags & 0x7800 == 0,
              flags & 0x0200 == 0, flags & 0x000f == 0,
              let questionCount = reader.readUInt16(), questionCount == 1,
              let answerCount = reader.readUInt16(),
              let authorityCount = reader.readUInt16(),
              let additionalCount = reader.readUInt16(),
              Int(answerCount) + Int(authorityCount) + Int(additionalCount) <= 128,
              reader.readName()?.lowercased() == queryName,
              reader.readUInt16() == 16, reader.readUInt16() == 1 else { return nil }

        var resolverAddresses = Set<String>()
        let recordCount = Int(answerCount) + Int(authorityCount) + Int(additionalCount)
        for index in 0..<recordCount {
            guard let owner = reader.readName(),
                  let type = reader.readUInt16(),
                  let recordClass = reader.readUInt16(),
                  reader.readUInt32() != nil,
                  let length = reader.readUInt16(),
                  let range = reader.readRange(Int(length)) else { return nil }
            guard index < Int(answerCount), owner.lowercased() == queryName,
                  type == 16, recordClass == 1 else { continue }
            guard let fields = txtFields(in: data[range]) else { return nil }
            for index in fields.indices where fields[index].lowercased() == "ns" {
                guard fields.index(after: index) < fields.endIndex else { continue }
                let candidate = fields[fields.index(after: index)]
                guard IPAddress.isPubliclyRoutable(candidate) else { continue }
                resolverAddresses.insert(candidate)
            }
        }
        guard resolverAddresses.count == 1 else { return nil }
        return resolverAddresses.first
    }

    /// Sends one bounded TXT query directly to the observed resolver endpoint.
    /// No shell, system resolver lookup, or user payload is involved.
    public static func observe(_ endpoint: DNSResolverEndpoint,
                               timeout: TimeInterval = 1.5) -> String? {
        if supportsDNSOverTLS(endpoint) {
            guard (0.1...3).contains(timeout),
                  let query = makeQuery(transactionID: UInt16.random(in: .min ... .max)) else { return nil }
            let transactionID = UInt16(query[0]) << 8 | UInt16(query[1])
            let exchange = DNSOverTLSExchange(endpoint: endpoint, query: query,
                                              transactionID: transactionID, timeout: timeout)
            return exchange.run()
        }
        guard supportsDirectUDP(endpoint), (0.1...3).contains(timeout),
              let query = makeQuery(transactionID: UInt16.random(in: .min ... .max)) else { return nil }
        let transactionID = UInt16(query[0]) << 8 | UInt16(query[1])
        let family = IPAddress.bytes(endpoint.host)?.first
        guard family == 4 || family == 6 else { return nil }
        let fd = socket(family == 4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        let seconds = Int(timeout)
        let microseconds = Int((timeout - Double(seconds)) * 1_000_000)
        var socketTimeout = timeval(tv_sec: seconds, tv_usec: Int32(microseconds))
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &socketTimeout,
                       socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &socketTimeout,
                       socklen_t(MemoryLayout<timeval>.size))
        guard connectSocket(fd, endpoint: endpoint, family: family!) else { return nil }
        let sent = query.withUnsafeBytes {
            Darwin.send(fd, $0.baseAddress, $0.count, 0)
        }
        guard sent == query.count else { return nil }
        var response = [UInt8](repeating: 0, count: maximumResponseBytes)
        let received = Darwin.recv(fd, &response, response.count, 0)
        guard received >= 12 else { return nil }
        return parseResponse(Data(response.prefix(received)), transactionID: transactionID)
    }

    private static func connectSocket(_ fd: Int32, endpoint: DNSResolverEndpoint,
                                      family: UInt8) -> Bool {
        if family == 4 {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = endpoint.port.bigEndian
            guard endpoint.host.withCString({ inet_pton(AF_INET, $0, &address.sin_addr) }) == 1 else {
                return false
            }
            return withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
                }
            }
        }
        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = endpoint.port.bigEndian
        guard endpoint.host.withCString({ inet_pton(AF_INET6, $0, &address.sin6_addr) }) == 1 else {
            return false
        }
        return withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) == 0
            }
        }
    }

    private static func makeQuery(transactionID: UInt16) -> Data? {
        var packet = Data()
        packet.append(UInt8(transactionID >> 8))
        packet.append(UInt8(truncatingIfNeeded: transactionID))
        packet.append(contentsOf: [0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in queryName.split(separator: ".") {
            guard (1...63).contains(label.utf8.count) else { return nil }
            packet.append(UInt8(label.utf8.count))
            packet.append(contentsOf: label.utf8)
        }
        packet.append(contentsOf: [0, 0, 16, 0, 1])
        return packet.count <= 512 ? packet : nil
    }

    private static func txtFields(in data: Data) -> [String]? {
        var fields: [String] = []
        let bytes = [UInt8](data)
        var cursor = 0
        while cursor < bytes.count {
            let length = Int(bytes[cursor])
            cursor += 1
            guard length > 0, cursor <= bytes.count, bytes.count - cursor >= length,
                  bytes[cursor..<(cursor + length)].allSatisfy({ $0 >= 0x20 && $0 < 0x7f }) else {
                return nil
            }
            fields.append(String(decoding: bytes[cursor..<(cursor + length)], as: UTF8.self))
            cursor += length
        }
        return fields.isEmpty ? nil : fields
    }
}

private final class DNSOverTLSExchange: @unchecked Sendable {
    private let endpoint: DNSResolverEndpoint
    private let query: Data
    private let transactionID: UInt16
    private let timeout: TimeInterval
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.safeclaude.dns-dot-probe")
    private let completed = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var started = false
    private var finished = false
    private var response = Data()
    private var result: String?

    init(endpoint: DNSResolverEndpoint, query: Data, transactionID: UInt16, timeout: TimeInterval) {
        self.endpoint = endpoint
        self.query = query
        self.transactionID = transactionID
        self.timeout = timeout
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        let authenticationName = endpoint.tlsServerName ??
            (IPAddress.bytes(endpoint.host) == nil ? endpoint.host : nil)
        authenticationName?.withCString {
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, $0)
        }
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let port = NWEndpoint.Port(rawValue: endpoint.port)!
        connection = NWConnection(host: NWEndpoint.Host(endpoint.host), port: port, using: parameters)
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
            let shouldSend = !started && !finished
            started = true
            lock.unlock()
            if shouldSend { sendQuery() }
        case .failed, .cancelled:
            finish(nil)
        default:
            break
        }
    }

    private func sendQuery() {
        var framed = Data([UInt8(query.count >> 8), UInt8(truncatingIfNeeded: query.count)])
        framed.append(query)
        connection.send(content: framed, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if error != nil { self.finish(nil) }
            else { self.receive() }
        })
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 2, maximumLength: 4_098) { [weak self] data, _, complete, error in
            guard let self else { return }
            if error != nil || complete || data == nil {
                self.finish(nil)
                return
            }
            self.lock.lock()
            guard !self.finished, let data else {
                self.lock.unlock()
                return
            }
            self.response.append(data)
            let expected: Int? = self.response.count >= 2
                ? (Int(self.response[0]) << 8 | Int(self.response[1])) + 2 : nil
            let tooLarge = self.response.count > 4_098 || (expected.map { $0 > 4_098 } ?? false)
            let enough = expected.map { self.response.count >= $0 } ?? false
            let frame = enough && expected == self.response.count ? self.response : nil
            self.lock.unlock()
            if tooLarge || (enough && frame == nil) {
                self.finish(nil)
            } else if let frame {
                self.finish(DNSResolverEgressProbe.parseStreamFrame(frame,
                    transactionID: self.transactionID))
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

private struct DNSResponseReader {
    private let bytes: [UInt8]
    private(set) var cursor = 0

    init(_ data: Data) { bytes = [UInt8](data) }

    mutating func readUInt16() -> UInt16? {
        guard cursor <= bytes.count, bytes.count - cursor >= 2 else { return nil }
        let value = UInt16(bytes[cursor]) << 8 | UInt16(bytes[cursor + 1])
        cursor += 2
        return value
    }

    mutating func readUInt32() -> UInt32? {
        guard cursor <= bytes.count, bytes.count - cursor >= 4 else { return nil }
        let value = UInt32(bytes[cursor]) << 24 | UInt32(bytes[cursor + 1]) << 16 |
            UInt32(bytes[cursor + 2]) << 8 | UInt32(bytes[cursor + 3])
        cursor += 4
        return value
    }

    mutating func skip(_ count: Int) -> Bool {
        guard count >= 0, cursor <= bytes.count, bytes.count - cursor >= count else { return false }
        cursor += count
        return true
    }

    mutating func readRange(_ count: Int) -> Range<Int>? {
        guard count >= 0, cursor <= bytes.count, bytes.count - cursor >= count else { return nil }
        let result = cursor..<(cursor + count)
        cursor += count
        return result
    }

    mutating func readName() -> String? {
        var scan = cursor
        var resume: Int?
        var visited = Set<Int>()
        var labels = 0
        var parts: [String] = []
        while true {
            guard scan < bytes.count else { return nil }
            let length = Int(bytes[scan])
            if length & 0xc0 == 0xc0 {
                guard scan + 1 < bytes.count else { return nil }
                let pointer = ((length & 0x3f) << 8) | Int(bytes[scan + 1])
                guard pointer < bytes.count, visited.insert(pointer).inserted else { return nil }
                if resume == nil { resume = scan + 2 }
                scan = pointer
                labels += 1
                guard labels <= 128 else { return nil }
                continue
            }
            guard length & 0xc0 == 0 else { return nil }
            scan += 1
            if length == 0 {
                cursor = resume ?? scan
                return parts.joined(separator: ".")
            }
            guard length <= 63, scan <= bytes.count, bytes.count - scan >= length,
                  bytes[scan..<(scan + length)].allSatisfy({ (0x21...0x7e).contains($0) }) else {
                return nil
            }
            parts.append(String(decoding: bytes[scan..<(scan + length)], as: UTF8.self))
            scan += length
            labels += 1
            guard labels <= 128, parts.joined(separator: ".").utf8.count <= 253 else { return nil }
        }
    }
}
