import Foundation
import XCTest
@testable import GuardCore

private actor Counter {
    var count = 0
    func increment() { count += 1 }
    func value() -> Int { count }
}
final class TraceCacheTests: XCTestCase {
    func testCoalescesOnlyEquivalentContextAndEpoch() async {
        let counter = Counter()
        let cache = TraceCache { target, _, _, _ in
            await counter.increment()
            try? await Task.sleep(for: .milliseconds(50))
            return TimedTrace(result: .observed(TraceObservation(targetHost: target.rawValue,
                ip: "192.0.2.1", countryCode: "US")), observedAt: Date())
        }
        let environment = ["HTTPS_PROXY": "http://user:secret@127.0.0.1:8000"]
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<10 { group.addTask { _ = await cache.observe(target: .api, environment: environment, epoch: 1, fingerprint: Data([1])) } }
        }
        let initial = await counter.value()
        XCTAssertEqual(initial, 1)
        _ = await cache.observe(target: .api, environment: environment, epoch: 2, fingerprint: Data([1]))
        _ = await cache.observe(target: .api, environment: [:], epoch: 2, fingerprint: Data([1]))
        _ = await cache.observe(target: .claudeAI, environment: environment, epoch: 2, fingerprint: Data([1]))
        _ = await cache.observe(target: .api, environment: environment, epoch: 2, fingerprint: Data([2]))
        _ = await cache.observe(target: .api, environment: environment, epoch: 2, fingerprint: Data([2]), family: .ipv6)
        _ = await cache.observe(target: .api, environment: environment, epoch: 2, fingerprint: Data([2]),
                                settingsEnvironment: ["https_proxy": "http://127.0.0.1:9000"])
        let final = await counter.value()
        XCTAssertEqual(final, 7)
    }
}
