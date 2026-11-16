import XCTest
import Security
@testable import GuardCore

final class NetworkTimeServiceRequirementTests: XCTestCase {
    func testRequirementIsValidAndBindsBundleAndTeam() {
        let requirement = NetworkTimeServiceRequirement.make(
            bundleIdentifier: "local.safeclaude.app",
            teamIdentifier: "HLA78V65US")
        XCTAssertEqual(requirement,
            "anchor apple generic and identifier \"local.safeclaude.app\" " +
            "and certificate leaf[subject.OU] = \"HLA78V65US\"")
        guard let requirement else { return XCTFail("Expected a signing requirement") }
        var parsed: SecRequirement?
        XCTAssertEqual(
            SecRequirementCreateWithString(requirement as CFString, SecCSFlags(), &parsed),
            errSecSuccess)
        XCTAssertNotNil(parsed)
    }

    func testRequirementRejectsMalformedBundleOrTeamIdentity() {
        XCTAssertNil(NetworkTimeServiceRequirement.make(
            bundleIdentifier: "local.safeclaude.app\" or always",
            teamIdentifier: "HLA78V65US"))
        XCTAssertNil(NetworkTimeServiceRequirement.make(
            bundleIdentifier: "local.safeclaude.app",
            teamIdentifier: "unknown"))
        XCTAssertNil(NetworkTimeServiceRequirement.make(
            bundleIdentifier: "SafeClaude",
            teamIdentifier: "HLA78V65US"))
    }
}
