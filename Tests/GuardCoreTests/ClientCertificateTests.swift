import Foundation
import XCTest
@testable import GuardCore

final class ClientCertificateTests: XCTestCase {
    func testPublicCertificateExpiryAndPrivateKeyFirstRejection() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let cert = root.appendingPathComponent("cert.pem")
        let key = root.appendingPathComponent("key.pem")
        let openssl = Process()
        openssl.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        openssl.arguments = ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
                             "-keyout", key.path, "-out", cert.path, "-days", "1", "-subj", "/CN=fixture"]
        openssl.standardOutput = FileHandle.nullDevice
        openssl.standardError = FileHandle.nullDevice
        try openssl.run()
        openssl.waitUntilExit()
        XCTAssertEqual(openssl.terminationStatus, 0)
        let now = Date()
        XCTAssertEqual(ClientCertificate.inspect(path: cert.path, at: now), .expiring)
        XCTAssertEqual(ClientCertificate.inspect(path: cert.path, at: now.addingTimeInterval(172_800)), .expired)
        XCTAssertEqual(ClientCertificate.inspect(path: cert.path, at: now.addingTimeInterval(-172_800)), .valid)
        // A PEM beginning with a private key is rejected before its body is read.
        XCTAssertNil(ClientCertificate.inspect(path: key.path))
        let rules = EnvironmentAssessment.observations(snapshot: LocalEnvironmentSnapshot.capture(),
            apiTrace: nil, reputation: nil, countryLanguages: nil, firstRun: nil, clientCertificate: .expired)
        XCTAssertEqual(rules.first { $0.id == "D08" }?.status, .triggered(.elevated, deduplicationKey: nil))
    }

    func testD08PassesOrIsNotApplicableOnlyAfterCompleteCertificateInspection() {
        let snapshot = LocalEnvironmentSnapshot.capture()
        func status(_ certificate: ClientCertificateStatus?,
                    configured: Bool?, unknown: Bool = false) -> ObservationStatus? {
            EnvironmentAssessment.observations(snapshot: snapshot,
                apiTrace: nil, reputation: nil, countryLanguages: nil, firstRun: nil,
                clientCertificate: certificate, clientCertificateConfigured: configured,
                clientCertificateUnknown: unknown).first { $0.id == "D08" }?.status
        }
        XCTAssertEqual(status(.valid, configured: true), .passed)
        XCTAssertEqual(status(nil, configured: false), .notApplicable)
        XCTAssertEqual(status(nil, configured: true),
                       .unknown(source: "client-certificate-unverified", critical: true))
        XCTAssertEqual(status(.valid, configured: true, unknown: true),
                       .unknown(source: "client-certificate-unverified", critical: true))
        XCTAssertEqual(status(.expired, configured: true, unknown: true),
                       .triggeredAndUnknown(.elevated, deduplicationKey: nil,
                                            source: "client-certificate-unverified", critical: true))
    }
}
