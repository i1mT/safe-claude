import Foundation
import XCTest
@testable import GuardCore

final class DNSResolverEgressProbeTests: XCTestCase {
    func testResolverTransportSelectionUsesExplicitStandardPorts() throws {
        let udp = try XCTUnwrap(DNSResolverEndpoint(host: "1.1.1.1", port: 53))
        let dot = try XCTUnwrap(DNSResolverEndpoint(host: "1.1.1.1", port: 853))
        let doh = try XCTUnwrap(DNSResolverEndpoint(host: "1.1.1.1", port: 443))
        XCTAssertTrue(DNSResolverEgressProbe.supportsDirectUDP(udp))
        XCTAssertFalse(DNSResolverEgressProbe.supportsDirectUDP(dot))
        XCTAssertFalse(DNSResolverEgressProbe.supportsDirectUDP(doh))
        XCTAssertTrue(DNSResolverEgressProbe.supportsDNSOverTLS(dot))
        XCTAssertFalse(DNSResolverEgressProbe.supportsDNSOverTLS(udp))
        XCTAssertFalse(DNSResolverEgressProbe.supportsDNSOverTLS(doh))
    }

    private func response(id: UInt16, fields: [(String, String)]) -> Data {
        var packet = Data([
            UInt8(id >> 8), UInt8(truncatingIfNeeded: id), 0x81, 0x80,
            0, 1, 0, 1, 0, 0, 0, 0
        ])
        for label in DNSResolverEgressProbe.queryName.split(separator: ".") {
            packet.append(UInt8(label.utf8.count))
            packet.append(contentsOf: label.utf8)
        }
        packet.append(contentsOf: [0, 0, 16, 0, 1])
        var data = Data()
        for (key, value) in fields {
            data.append(UInt8(key.utf8.count))
            data.append(contentsOf: key.utf8)
            data.append(UInt8(value.utf8.count))
            data.append(contentsOf: value.utf8)
        }
        packet.append(contentsOf: [0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0])
        packet.append(UInt8(data.count >> 8))
        packet.append(UInt8(truncatingIfNeeded: data.count))
        packet.append(data)
        return packet
    }

    func testReadsOnlyAkamaiResolverEgressFieldFromTXTAnswer() {
        let packet = response(id: 0x1234, fields: [
            ("ecs", "203.0.113.88"), ("ns", "8.8.8.8"), ("ip", "203.0.113.99")
        ])
        XCTAssertEqual(DNSResolverEgressProbe.parseResponse(packet, transactionID: 0x1234), "8.8.8.8")
        XCTAssertNil(DNSResolverEgressProbe.parseResponse(packet, transactionID: 0x1235))
    }

    func testDNSOverTLSFrameRequiresOneCompleteBoundedResponse() {
        let dns = response(id: 0x1234, fields: [("ns", "8.8.8.8")])
        let frame = Data([UInt8(dns.count >> 8), UInt8(truncatingIfNeeded: dns.count)]) + dns
        XCTAssertEqual(DNSResolverEgressProbe.parseStreamFrame(frame, transactionID: 0x1234), "8.8.8.8")
        XCTAssertNil(DNSResolverEgressProbe.parseStreamFrame(Data(frame.dropLast()), transactionID: 0x1234))
        XCTAssertNil(DNSResolverEgressProbe.parseStreamFrame(frame + Data([0]), transactionID: 0x1234))
        XCTAssertNil(DNSResolverEgressProbe.parseStreamFrame(
            Data([0xff, 0xff]) + dns, transactionID: 0x1234))
        XCTAssertNil(DNSResolverEgressProbe.parseStreamFrame(frame, transactionID: 0x4321))
    }

    func testRejectsPrivateOrAmbiguousResolverEgressAndMalformedTXT() {
        XCTAssertNil(DNSResolverEgressProbe.parseResponse(
            response(id: 9, fields: [("ns", "192.168.1.1")]), transactionID: 9))
        XCTAssertNil(DNSResolverEgressProbe.parseResponse(
            response(id: 9, fields: [("ns", "8.8.8.8"), ("ns", "1.1.1.1")]), transactionID: 9))
        XCTAssertNil(DNSResolverEgressProbe.parseResponse(
            response(id: 9, fields: [("ecs", "8.8.8.8")]), transactionID: 9))
        var truncated = response(id: 9, fields: [("ns", "8.8.8.8")])
        truncated.removeLast()
        XCTAssertNil(DNSResolverEgressProbe.parseResponse(truncated, transactionID: 9))
    }

    func testRejectsResponseForDifferentQuestionAndNonAnswerTXT() {
        var wrongQuestion = response(id: 9, fields: [("ns", "8.8.8.8")])
        wrongQuestion[13] = Character("x").asciiValue!
        XCTAssertNil(DNSResolverEgressProbe.parseResponse(wrongQuestion, transactionID: 9))

        var authorityOnly = response(id: 9, fields: [("ns", "8.8.8.8")])
        authorityOnly[7] = 0
        authorityOnly[9] = 1
        XCTAssertNil(DNSResolverEgressProbe.parseResponse(authorityOnly, transactionID: 9))
    }

    func testResolverEndpointNormalizesIPv4AndIPv6() throws {
        let ipv4 = try XCTUnwrap(DNSResolverEndpoint(host: "8.8.8.8", port: 53))
        XCTAssertEqual(ipv4.identity, "8.8.8.8|53")
        let ipv6 = try XCTUnwrap(DNSResolverEndpoint(host: "2001:0db8:0:0:0:0:0:1", port: 53))
        XCTAssertEqual(ipv6.host, "2001:db8::1")
        XCTAssertNil(DNSResolverEndpoint(host: "not an address", port: 53))
    }

    func testPubliclyRoutableFilterExcludesPrivateAndDocumentationRanges() {
        XCTAssertTrue(IPAddress.isPubliclyRoutable("8.8.8.8"))
        XCTAssertFalse(IPAddress.isPubliclyRoutable("192.168.1.1"))
        XCTAssertFalse(IPAddress.isPubliclyRoutable("2001:db8::1"))
        XCTAssertTrue(IPAddress.isPubliclyRoutable("2606:4700:4700::1111"))
    }
}
