import Foundation
import Security
import XCTest
@testable import GuardCore

final class DNSOverHTTPSProbeTests: XCTestCase {
    private func testTrust() throws -> SecTrust {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "doh-test-cert", withExtension: "pem"))
        let pem = try String(contentsOf: url, encoding: .utf8)
        let der = try XCTUnwrap(Data(base64Encoded: pem.components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") }.joined()))
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil, der as CFData))
        var trust: SecTrust?
        XCTAssertEqual(SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust),
                       errSecSuccess)
        let value = try XCTUnwrap(trust)
        XCTAssertEqual(SecTrustSetAnchorCertificates(value, [certificate] as CFArray), errSecSuccess)
        XCTAssertEqual(SecTrustSetAnchorCertificatesOnly(value, true), errSecSuccess)
        // The fixture is valid in this fixed window, keeping the hostname test
        // independent from the machine clock and certificate generation time.
        XCTAssertEqual(SecTrustSetVerifyDate(
            value, Date(timeIntervalSince1970: 1_800_000_000) as CFDate), errSecSuccess)
        return value
    }

    private func dnsResponse(id: UInt16) -> Data {
        var packet = Data([
            UInt8(id >> 8), UInt8(truncatingIfNeeded: id), 0x81, 0x80,
            0, 1, 0, 1, 0, 0, 0, 0
        ])
        for label in DNSResolverEgressProbe.queryName.split(separator: ".") {
            packet.append(UInt8(label.utf8.count))
            packet.append(contentsOf: label.utf8)
        }
        packet.append(contentsOf: [0, 0, 16, 0, 1, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0, 0, 11])
        packet.append(contentsOf: [2] + Array("ns".utf8) + [7] + Array("8.8.8.8".utf8))
        return packet
    }

    private func http(_ body: Data, headers: String = "") -> Data {
        Data(("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(body.count)\r\n"
              + headers + "\r\n").utf8) + body
    }

    func testParsesOneBoundedDNSMessageResponse() {
        let body = dnsResponse(id: 0x7812)
        XCTAssertEqual(DNSOverHTTPSProbe.parseHTTPResponse(
            http(body, headers: "Cache-Control: no-store\r\n"), transactionID: 0x7812), "8.8.8.8")
        XCTAssertNil(DNSOverHTTPSProbe.parseHTTPResponse(http(body), transactionID: 0x1278))
    }

    func testRejectsAmbiguousOrUnsupportedHTTPFraming() {
        let body = dnsResponse(id: 7)
        XCTAssertNil(DNSOverHTTPSProbe.parseHTTPResponse(
            http(body, headers: "Transfer-Encoding: chunked\r\n"), transactionID: 7))
        XCTAssertNil(DNSOverHTTPSProbe.parseHTTPResponse(
            http(body, headers: "Content-Length: 12\r\n"), transactionID: 7))
        XCTAssertNil(DNSOverHTTPSProbe.parseHTTPResponse(
            Data("HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n".utf8), transactionID: 7))
        XCTAssertNil(DNSOverHTTPSProbe.parseHTTPResponse(
            Data("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n".utf8),
            transactionID: 7))
        XCTAssertNil(DNSOverHTTPSProbe.parseHTTPResponse(http(body.dropLast()), transactionID: 7))
        XCTAssertNil(DNSOverHTTPSProbe.parseHTTPResponse(http(body) + Data([0]), transactionID: 7))
    }

    func testDoHRequestAcceptsOnlyHTTPSConfiguredEndpointsAndLiteralServerIPs() {
        XCTAssertNil(DNSOverHTTPSProbe.observe(
            serverURL: URL(string: "http://resolver.example/dns-query")!,
            serverIP: "192.0.2.1"))
        XCTAssertNil(DNSOverHTTPSProbe.observe(
            serverURL: URL(string: "https://user@resolver.example/dns-query")!,
            serverIP: "192.0.2.1"))
        XCTAssertNil(DNSOverHTTPSProbe.observe(
            serverURL: URL(string: "https://resolver.example/dns-query")!,
            serverIP: "resolver.example"))
        XCTAssertEqual(DNSResolverEgressProbe.diagnosticQuery(transactionID: 9)?.count, 39)
    }

    func testDoHTLSRequiresConfiguredURLHostnameInTrustedCertificate() throws {
        let matchingHostTrust = try testTrust()
        let otherHostTrust = try testTrust()
        let matchingHostAccepted = DNSOverHTTPSTrust.evaluate(
            matchingHostTrust, serverName: "doh.safeclaude.test")
        if !matchingHostAccepted {
            var error: CFError?
            _ = SecTrustEvaluateWithError(matchingHostTrust, &error)
            XCTFail("Expected the trusted DoH hostname to pass: \(String(describing: error))")
        }
        XCTAssertFalse(DNSOverHTTPSTrust.evaluate(otherHostTrust, serverName: "other.safeclaude.test"))
    }
}
