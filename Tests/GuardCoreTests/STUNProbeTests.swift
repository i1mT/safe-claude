import XCTest
@testable import GuardCore

final class STUNProbeTests: XCTestCase {
    func testEndpointValidationRejectsURLsCredentialsAndInvalidPorts() {
        XCTAssertEqual(STUNProbe.validate(endpoint: "StUn.Example:3478")?.host, "stun.example")
        XCTAssertNil(STUNProbe.validate(endpoint: "https://stun.example:3478"))
        XCTAssertNil(STUNProbe.validate(endpoint: "user@stun.example:3478"))
        XCTAssertNil(STUNProbe.validate(endpoint: "stun.example:0"))
        XCTAssertNil(STUNProbe.validate(endpoint: "stun.example:65536"))
    }

    func testBindingResponseRequiresValidHeaderTransactionAndMappedAddress() throws {
        let transaction = Array(0..<12).map(UInt8.init)
        let attributes: [UInt8] = [
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01,
            UInt8((3478 ^ 0x2112) >> 8), UInt8((3478 ^ 0x2112) & 0xff),
            0x21 ^ 1, 0x12 ^ 2, 0xa4 ^ 3, 0x42 ^ 4
        ]
        var bytes: [UInt8] = [
            0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42
        ] + transaction + attributes
        XCTAssertEqual(STUNProbe.decode(Data(bytes), transaction: transaction), "1.2.3.4")
        XCTAssertNil(STUNProbe.decode(Data(bytes), transaction: Array(repeating: 9, count: 12)))
        bytes[1] = 0x11
        XCTAssertNil(STUNProbe.decode(Data(bytes), transaction: transaction))
        bytes[1] = 0x01
        bytes[3] = 0x0b
        XCTAssertNil(STUNProbe.decode(Data(bytes), transaction: transaction))
    }
}
