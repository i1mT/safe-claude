import Darwin
import Foundation
import Security

public struct STUNObservation: Sendable, Equatable {
    public let mappedAddress: String
    public let observedAt: Date
}

/// A bounded RFC 8489 Binding probe. The returned address is held only in
/// memory and must not be included in reports or logs.
public enum STUNProbe {
    public static let defaultEndpoint = "stun.cloudflare.com:3478"
    private static let magicCookie: UInt32 = 0x2112A442

    public static func validate(endpoint: String) -> (host: String, port: UInt16)? {
        guard endpoint.utf8.count <= 253, !endpoint.contains("/"), !endpoint.contains("@"),
              !endpoint.contains("?"), !endpoint.contains("#"), !endpoint.contains(" "),
              let colon = endpoint.lastIndex(of: ":") else { return nil }
        let host = String(endpoint[..<colon]).lowercased()
        let portText = String(endpoint[endpoint.index(after: colon)...])
        guard !host.isEmpty, host.utf8.count <= 253,
              host.utf8.allSatisfy({ ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 46 }),
              let portValue = UInt16(portText), portValue > 0 else { return nil }
        return (host, portValue)
    }

    public static func probe(endpoint: String = defaultEndpoint, timeout: TimeInterval = 2) -> STUNObservation? {
        guard let endpoint = validate(endpoint: endpoint), timeout > 0, timeout <= 3 else { return nil }
        var hints = addrinfo(ai_flags: AI_ADDRCONFIG, ai_family: AF_UNSPEC, ai_socktype: SOCK_DGRAM,
                             ai_protocol: IPPROTO_UDP, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil,
                             ai_next: nil)
        var resolved: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(endpoint.host, String(endpoint.port), &hints, &resolved) == 0,
              let first = resolved else { return nil }
        defer { freeaddrinfo(first) }

        var transaction = [UInt8](repeating: 0, count: 12)
        guard SecRandomCopyBytes(kSecRandomDefault, transaction.count, &transaction) == errSecSuccess else { return nil }
        var request = [UInt8](repeating: 0, count: 20)
        request[0] = 0x00; request[1] = 0x01
        request[4] = 0x21; request[5] = 0x12; request[6] = 0xA4; request[7] = 0x42
        request.replaceSubrange(8..<20, with: transaction)

        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let item = cursor {
            let fd = socket(item.pointee.ai_family, SOCK_DGRAM, IPPROTO_UDP)
            if fd >= 0 {
                defer { close(fd) }
                var tv = timeval(tv_sec: Int(timeout), tv_usec: __darwin_suseconds_t((timeout.truncatingRemainder(dividingBy: 1) * 1_000_000).rounded()))
                _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                guard connect(fd, item.pointee.ai_addr, item.pointee.ai_addrlen) == 0 else {
                    cursor = item.pointee.ai_next
                    continue
                }
                let sent = request.withUnsafeBytes { bytes in
                    send(fd, bytes.baseAddress, bytes.count, 0)
                }
                if sent == request.count {
                    var response = [UInt8](repeating: 0, count: 2048)
                    let count = Darwin.recv(fd, &response, response.count, 0)
                    if count >= 20, let address = decode(Data(response.prefix(count)), transaction: transaction) {
                        return STUNObservation(mappedAddress: address, observedAt: Date())
                    }
                }
            }
            cursor = item.pointee.ai_next
        }
        return nil
    }

    public static func decode(_ data: Data, transaction: [UInt8]) -> String? {
        let b = [UInt8](data)
        guard transaction.count == 12, b.count >= 20, b.count <= 2048,
              b[0] == 0x01, b[1] == 0x01,
              b[4...7].elementsEqual([0x21, 0x12, 0xA4, 0x42]),
              b[8..<20].elementsEqual(transaction) else { return nil }
        let length = Int(b[2]) << 8 | Int(b[3])
        guard length == b.count - 20, length % 4 == 0 else { return nil }
        var offset = 20
        while offset + 4 <= b.count {
            let type = Int(b[offset]) << 8 | Int(b[offset + 1])
            let size = Int(b[offset + 2]) << 8 | Int(b[offset + 3])
            offset += 4
            guard size <= b.count - offset else { return nil }
            if type == 0x0020 {
                guard size == 8 || size == 20 else { return nil }
                let family = b[offset + 1]
                let port = (Int(b[offset + 2]) << 8 | Int(b[offset + 3])) ^ 0x2112
                guard (1...65535).contains(port) else { return nil }
                if family == 0x01, size == 8 {
                    let cookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
                    let octets = (0..<4).map { b[offset + 4 + $0] ^ cookie[$0] }
                    return octets.map(String.init).joined(separator: ".")
                }
                if family == 0x02, size == 20 {
                    var bytes = (0..<16).map { b[offset + 4 + $0] }
                    let mask: [UInt8] = [0x21, 0x12, 0xA4, 0x42] + Array(transaction)
                    for index in bytes.indices { bytes[index] ^= mask[index] }
                    var address = in6_addr()
                    withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: bytes) }
                    var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    guard inet_ntop(AF_INET6, &address, &output, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
                    let end = output.firstIndex(of: 0) ?? output.endIndex
                    return String(decoding: output[..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self)
                }
                return nil
            }
            let paddedSize = (size + 3) & ~3
            guard paddedSize <= b.count - offset else { return nil }
            offset += paddedSize
        }
        return nil
    }
}

actor STUNCache {
    static let shared = STUNCache()
    private var entries: [String: STUNObservation] = [:]
    private var flights: [String: Task<STUNObservation?, Never>] = [:]

    func observe(endpoint: String) async -> STUNObservation? {
        if let value = entries[endpoint], (0...5).contains(Date().timeIntervalSince(value.observedAt)) {
            return value
        }
        if let flight = flights[endpoint] { return await flight.value }
        let flight = Task.detached(priority: .utility) { STUNProbe.probe(endpoint: endpoint) }
        flights[endpoint] = flight
        let value = await flight.value
        flights[endpoint] = nil
        if let value { entries[endpoint] = value }
        return value
    }
}
