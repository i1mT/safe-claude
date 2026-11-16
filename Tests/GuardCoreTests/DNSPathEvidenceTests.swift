import Foundation
import XCTest
@testable import GuardCore

final class DNSPathEvidenceTests: XCTestCase {
    private func record(_ time: Date = Date(), pid: pid_t = 123) -> DNSPathEvidence {
        let resolver = DNSPathEvidence.resolverIdentity(host: "192.0.2.53", port: 53)!
        return DNSPathEvidence(pid: pid, pidVersion: 4, processStartSeconds: 100,
            processStartMicroseconds: 10, domainClass: .anthropicAPI, transport: .udp,
            resolverIdentity: resolver, observedAt: time)
    }

    func testSpoolAppendsDrainsAndRemovesStaleEvidence() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let spool = DNSPathEvidenceSpool(containerURL: directory)
        let now = Date()
        try spool.append(record(now.addingTimeInterval(-4)))
        try spool.append(record(now.addingTimeInterval(-45), pid: 124))

        let fresh = try spool.drain(now: now)
        XCTAssertEqual(fresh.count, 1)
        XCTAssertEqual(fresh[0].pid, 123)
        XCTAssertTrue(try spool.drain(now: now).isEmpty)
    }

    func testSpoolBoundsQueueAndPersistsOnlyResolverDigest() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let spool = DNSPathEvidenceSpool(containerURL: directory)
        for index in 0..<(DNSPathEvidenceSpool.maximumRecords + 5) {
            try spool.append(record(Date(), pid: pid_t(index + 2)))
        }
        XCTAssertEqual(try spool.drain().count, DNSPathEvidenceSpool.maximumRecords)
        let stored = try String(contentsOf: directory.appendingPathComponent("dns-path-evidence.json"),
                                encoding: .utf8)
        XCTAssertFalse(stored.contains("192.0.2.53"))
        XCTAssertFalse(stored.contains("api.anthropic.com"))
        XCTAssertEqual(DNSPathEvidence.digest("resolver"), DNSPathEvidence.digest("resolver"))
        XCTAssertNotEqual(DNSPathEvidence.digest("resolver"), DNSPathEvidence.digest("other"))
    }

    func testDoHCountryEvidenceContainsOnlyCountryAndResolverDigests() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let now = Date()
        let item = DNSPathEvidence(pid: 123, pidVersion: 4, processStartSeconds: 100,
            processStartMicroseconds: 200, domainClass: .anthropicAPI, transport: .udp,
            resolverIdentity: "192.0.2.53|53", resolverSecurity: .dnsOverHTTPS,
            resolverCountryCode: "US", resolverCountryResolverIdentity: "198.51.100.53|443",
            resolverCountryObservedAt: now, observedAt: now)
        let path = directory.appendingPathComponent("dns-path-evidence.json")
        try DNSPathEvidenceSpool(containerURL: directory).append(item)
        let stored = try String(contentsOf: path, encoding: .utf8)
        XCTAssertTrue(stored.contains("\"resolverCountryCode\":\"US\""))
        XCTAssertFalse(stored.contains("192.0.2.53"))
        XCTAssertFalse(stored.contains("198.51.100.53"))
        let decoded = try XCTUnwrap(DNSPathEvidenceSpool(containerURL: directory).drain().first)
        XCTAssertEqual(decoded.resolverCountryResolverDigest,
                       DNSPathEvidence.digest("198.51.100.53|443"))
    }

    func testFreshDNSPathRecordCarriesPriorCountryWithoutRefreshingItsAge() throws {
        let countryAt = Date().addingTimeInterval(-10)
        let sample = record(countryAt).carryingResolverCountry(
            "US", resolverIdentity: "198.51.100.53|443", observedAt: countryAt)
        let refreshedPath = record(Date())
        let merged = refreshedPath.carryingResolverCountry(from: sample)
        XCTAssertEqual(merged.resolverCountryCode, "US")
        XCTAssertEqual(merged.resolverCountryResolverDigest, DNSPathEvidence.digest("198.51.100.53|443"))
        XCTAssertEqual(merged.resolverCountryObservedAt, countryAt)
        XCTAssertNotEqual(merged.observedAt, countryAt)
    }

    func testLegacyEncryptedResolverEvidenceRemainsReadableAfterProtocolGranularityUpgrade() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let evidence = record()
        let encoded = try JSONEncoder().encode([evidence])
        var objects = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [[String: Any]])
        objects[0]["resolverSecurity"] = "encrypted"
        let legacyData = try JSONSerialization.data(withJSONObject: objects)
        let path = directory.appendingPathComponent("dns-path-evidence.json")
        try legacyData.write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)

        let decoded = try DNSPathEvidenceSpool(containerURL: directory).drain()
        XCTAssertEqual(decoded.first?.resolverSecurity, .encrypted)
    }

    func testEvidenceRequiresFreshMatchingSessionBirthIdentity() throws {
        let current = try XCTUnwrap(ProcessIdentity.read(getpid(), ownedBy: getuid()))
        let session = SessionRecord(identity: current, executable: current.executable, isTopLevel: true)
        let fresh = DNSPathEvidence(pid: current.pid, pidVersion: 7,
            processStartSeconds: current.startSeconds,
            processStartMicroseconds: current.startMicroseconds,
            domainClass: .anthropicAPI, transport: .tcp,
            resolverIdentity: "resolver", observedAt: Date())
        XCTAssertTrue(fresh.matches(current, session: session))

        let reusedPID = DNSPathEvidence(pid: current.pid, pidVersion: 7,
            processStartSeconds: current.startSeconds &+ 1,
            processStartMicroseconds: current.startMicroseconds,
            domainClass: .anthropicAPI, transport: .tcp,
            resolverIdentity: "resolver", observedAt: Date())
        XCTAssertFalse(reusedPID.matches(current, session: session))

        let stale = DNSPathEvidence(pid: current.pid, pidVersion: 7,
            processStartSeconds: current.startSeconds,
            processStartMicroseconds: current.startMicroseconds,
            domainClass: .anthropicAPI, transport: .tcp,
            resolverIdentity: "resolver", observedAt: Date().addingTimeInterval(-31))
        XCTAssertFalse(stale.matches(current, session: session))
    }

    func testResolverVerdictRequiresConfiguredResolverEvidence() {
        let evidence = record()
        XCTAssertEqual(evidence.resolverVerdict(configuredResolverDigests: nil), .unknown)
        XCTAssertEqual(evidence.resolverVerdict(configuredResolverDigests: []), .unknown)
        XCTAssertEqual(evidence.resolverVerdict(
            configuredResolverDigests: [evidence.resolverDigest]), .matchesConfiguredPath)
        XCTAssertEqual(evidence.resolverVerdict(
            configuredResolverDigests: [DNSPathEvidence.digest("different")]), .bypassesConfiguredPath)
    }
}
