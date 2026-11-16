import Foundation

/// Extracts DNS questions without retaining the packet or query name.
/// The result is intended for an in-memory allowlist check inside a DNS flow
/// provider; callers must never persist the packet or returned name.
public enum DNSQuestionParser {
    private static let protectedDomains = [
        "api.anthropic.com", "claude.ai", "claude.com", "platform.claude.com"
    ]

    public enum ParseError: Error, Equatable, Sendable {
        case truncatedHeader
        case notAQuery
        case truncatedQuestion
        case invalidName
        case compressionLoop
        case unsupportedQuestionCount
    }

    public static func questions(in packet: Data) throws -> [String] {
        let bytes = [UInt8](packet)
        guard bytes.count >= 12 else { throw ParseError.truncatedHeader }
        let flags = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
        guard flags & 0x8000 == 0 else { throw ParseError.notAQuery }
        let count = Int(UInt16(bytes[4]) << 8 | UInt16(bytes[5]))
        guard count <= 64 else { throw ParseError.unsupportedQuestionCount }

        var cursor = 12
        var result: [String] = []
        result.reserveCapacity(count)
        for _ in 0..<count {
            let (name, end) = try decodeName(bytes, at: cursor)
            guard end <= bytes.count, bytes.count - end >= 4 else {
                throw ParseError.truncatedQuestion
            }
            cursor = end + 4 // QTYPE and QCLASS
            result.append(name)
        }
        return result
    }

    /// Parses one complete DNS-over-TCP frame (two-byte length prefix included).
    public static func questions(inTCPFrame frame: Data) throws -> [String] {
        guard frame.count >= 2 else { throw ParseError.truncatedHeader }
        let bytes = [UInt8](frame)
        let declaredLength = Int(bytes[0]) << 8 | Int(bytes[1])
        guard declaredLength == frame.count - 2 else { throw ParseError.truncatedQuestion }
        return try questions(in: frame.subdata(in: 2..<frame.count))
    }

    /// Exact domain or a true subdomain match; e.g. `notclaude.ai` does not match.
    public static func isProtectedDomain(_ name: String) -> Bool {
        let normalized = name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return protectedDomains.contains { normalized == $0 || normalized.hasSuffix("." + $0) }
    }

    private static func decodeName(_ bytes: [UInt8], at start: Int) throws -> (String, Int) {
        var labels: [String] = []
        var cursor = start
        var resume: Int?
        var visited = Set<Int>()
        var expandedLength = 0

        while true {
            guard cursor < bytes.count else { throw ParseError.invalidName }
            let length = Int(bytes[cursor])
            if length & 0xC0 == 0xC0 {
                guard cursor + 1 < bytes.count else { throw ParseError.invalidName }
                let pointer = ((length & 0x3F) << 8) | Int(bytes[cursor + 1])
                guard pointer < bytes.count else { throw ParseError.invalidName }
                guard visited.insert(pointer).inserted else { throw ParseError.compressionLoop }
                if resume == nil { resume = cursor + 2 }
                cursor = pointer
                continue
            }
            guard length & 0xC0 == 0 else { throw ParseError.invalidName }
            cursor += 1
            if length == 0 { break }
            guard length <= 63, cursor <= bytes.count, bytes.count - cursor >= length else {
                throw ParseError.invalidName
            }
            expandedLength += length + 1
            guard expandedLength <= 254 else { throw ParseError.invalidName }
            let labelBytes = bytes[cursor..<(cursor + length)]
            guard labelBytes.allSatisfy({ $0 > 0x20 && $0 < 0x7f && $0 != 0x2e }) else {
                throw ParseError.invalidName
            }
            labels.append(String(decoding: labelBytes, as: UTF8.self).lowercased())
            cursor += length
        }
        return (labels.joined(separator: "."), resume ?? cursor)
    }
}

/// Incrementally decodes DNS-over-TCP client streams. It retains only bytes
/// needed to complete an incomplete frame and emits parsed question names.
public struct DNSOverTCPFrameDecoder: Sendable {
    public enum DecodeError: Error, Equatable, Sendable {
        case emptyFrame
        case bufferLimitExceeded
    }

    public static let maximumBufferedBytes = 131_074
    private var buffer = Data()

    public init() {}

    public mutating func append(_ chunk: Data) throws -> [[String]] {
        guard chunk.count <= Self.maximumBufferedBytes,
              buffer.count <= Self.maximumBufferedBytes - chunk.count else {
            throw DecodeError.bufferLimitExceeded
        }
        buffer.append(chunk)
        var cursor = 0
        var decoded: [[String]] = []
        while buffer.count - cursor >= 2 {
            let length = Int(buffer[cursor]) << 8 | Int(buffer[cursor + 1])
            guard length > 0 else { throw DecodeError.emptyFrame }
            guard buffer.count - cursor - 2 >= length else { break }
            let end = cursor + 2 + length
            decoded.append(try DNSQuestionParser.questions(
                inTCPFrame: buffer.subdata(in: cursor..<end)
            ))
            cursor = end
        }
        if cursor > 0 { buffer.removeSubrange(0..<cursor) }
        return decoded
    }

    public var pendingByteCount: Int { buffer.count }
}
