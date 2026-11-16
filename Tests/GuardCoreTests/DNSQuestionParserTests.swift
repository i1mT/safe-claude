import XCTest
@testable import GuardCore

final class DNSQuestionParserTests: XCTestCase {
    func testParsesAndNormalizesQuestionWithoutKeepingPacket() throws {
        let packet = query(labels: ["API", "Anthropic", "COM"])
        XCTAssertEqual(try DNSQuestionParser.questions(in: packet), ["api.anthropic.com"])
    }

    func testParsesCompressedQuestionName() throws {
        var packet = query(labels: ["api", "anthropic", "com"])
        // Add a second question whose name points to the first question.
        packet[5] = 2
        packet.removeLast(4)
        packet.append(contentsOf: [0, 1, 0, 1])
        packet.append(contentsOf: [0xC0, 0x0C, 0, 1, 0, 1])
        XCTAssertEqual(try DNSQuestionParser.questions(in: packet),
                       ["api.anthropic.com", "api.anthropic.com"])
    }

    func testRejectsResponseAndTruncatedQuestion() {
        var response = query(labels: ["api", "anthropic", "com"])
        response[2] = 0x80
        XCTAssertThrowsError(try DNSQuestionParser.questions(in: response)) {
            XCTAssertEqual($0 as? DNSQuestionParser.ParseError, .notAQuery)
        }
        XCTAssertThrowsError(try DNSQuestionParser.questions(in: Data([0, 1, 0])))
    }

    func testRejectsCompressionLoop() {
        var packet = Data(repeating: 0, count: 18)
        packet[5] = 1
        packet[12] = 0xC0
        packet[13] = 0x0C
        XCTAssertThrowsError(try DNSQuestionParser.questions(in: packet)) {
            XCTAssertEqual($0 as? DNSQuestionParser.ParseError, .compressionLoop)
        }
    }

    func testProtectedDomainMatchingUsesLabelBoundaries() {
        XCTAssertTrue(DNSQuestionParser.isProtectedDomain("API.ANTHROPIC.COM"))
        XCTAssertTrue(DNSQuestionParser.isProtectedDomain("edge.api.anthropic.com"))
        XCTAssertFalse(DNSQuestionParser.isProtectedDomain("notanthropic.com"))
        XCTAssertFalse(DNSQuestionParser.isProtectedDomain("claude.ai.attacker.example"))
    }

    func testTCPFrameRequiresOneCompleteLengthPrefixedMessage() throws {
        let dns = query(labels: ["api", "anthropic", "com"])
        let frame = Data([UInt8(dns.count >> 8), UInt8(dns.count & 0xff)]) + dns
        XCTAssertEqual(try DNSQuestionParser.questions(inTCPFrame: frame), ["api.anthropic.com"])
        XCTAssertThrowsError(try DNSQuestionParser.questions(inTCPFrame: Data([0, 12])))
        XCTAssertThrowsError(try DNSQuestionParser.questions(inTCPFrame: Data([0])))
    }

    func testTCPStreamDecoderHandlesFragmentationAndCoalescing() throws {
        let firstDNS = query(labels: ["api", "anthropic", "com"])
        let secondDNS = query(labels: ["claude", "ai"])
        let first = Data([UInt8(firstDNS.count >> 8), UInt8(firstDNS.count & 0xff)]) + firstDNS
        let second = Data([UInt8(secondDNS.count >> 8), UInt8(secondDNS.count & 0xff)]) + secondDNS
        var decoder = DNSOverTCPFrameDecoder()

        XCTAssertEqual(try decoder.append(first.prefix(1)), [])
        XCTAssertEqual(try decoder.append(first.dropFirst().prefix(6)), [])
        XCTAssertEqual(decoder.pendingByteCount, 7)
        XCTAssertEqual(try decoder.append(first.dropFirst(7) + second),
                       [["api.anthropic.com"], ["claude.ai"]])
        XCTAssertEqual(decoder.pendingByteCount, 0)
    }

    func testTCPStreamDecoderBoundsBufferAndRejectsEmptyFrame() throws {
        var decoder = DNSOverTCPFrameDecoder()
        XCTAssertThrowsError(try decoder.append(Data(repeating: 0, count:
            DNSOverTCPFrameDecoder.maximumBufferedBytes + 1))) {
            XCTAssertEqual($0 as? DNSOverTCPFrameDecoder.DecodeError, .bufferLimitExceeded)
        }
        XCTAssertThrowsError(try decoder.append(Data([0, 0]))) {
            XCTAssertEqual($0 as? DNSOverTCPFrameDecoder.DecodeError, .emptyFrame)
        }
    }

    private func query(labels: [String]) -> Data {
        var bytes: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in labels {
            let value = Array(label.utf8)
            bytes.append(UInt8(value.count))
            bytes += value
        }
        bytes += [0, 0, 1, 0, 1]
        return Data(bytes)
    }
}
