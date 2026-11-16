import Foundation
import NetworkExtension
import ObjectiveC
import SystemExtensions
import GuardCore

@MainActor
final class DNSProxyEnrollment: ObservableObject {
    enum State: Equatable {
        case inactive
        case requestingExtensionApproval
        case configuringDNSProxy
        case active
        case failed(String)
    }

    @Published private(set) var state: State = .inactive

    private var extensionIdentifier: String? {
        Bundle.main.bundleIdentifier.map { $0 + ".dnsproxy" }
    }

    func refresh() async {
        do {
            let manager = NEDNSProxyManager.shared()
            try await load(manager)
            state = manager.isEnabled &&
                manager.providerProtocol?.providerBundleIdentifier == extensionIdentifier
                ? .active : .inactive
        } catch {
            state = .failed("无法读取 DNS Proxy 状态")
        }
    }

    func enable() async {
        guard let extensionIdentifier else {
            state = .failed("App bundle identifier 不可用")
            return
        }
        state = .requestingExtensionApproval
        do {
            _ = try await SystemExtensionRequest.submit(
                .activationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
            )
            state = .configuringDNSProxy
            let manager = NEDNSProxyManager.shared()
            try await load(manager)
            let provider = NEDNSProxyProviderProtocol()
            provider.providerBundleIdentifier = extensionIdentifier
            manager.providerProtocol = provider
            manager.localizedDescription = "SafeClaude DNS Monitor"
            manager.isEnabled = true
            try await save(manager)
            try await load(manager)
            guard manager.isEnabled,
                  manager.providerProtocol?.providerBundleIdentifier == extensionIdentifier else {
                throw EnrollmentError.configurationDidNotPersist
            }
            state = .active
        } catch {
            state = .failed(Self.safeMessage(for: error))
        }
    }

    func disable() async {
        do {
            try await removeForUninstall()
        } catch {
            state = .failed(Self.safeMessage(for: error))
        }
    }

    func removeForUninstall() async throws {
        guard let extensionIdentifier else {
            throw EnrollmentError.bundleIdentifierUnavailable
        }
        DNSResolverProbeConsent.setAllowed(false)
        state = .configuringDNSProxy
        let manager = NEDNSProxyManager.shared()
        try await load(manager)
        let previousProvider = manager.providerProtocol
        let previousDescription = manager.localizedDescription
        let previousEnabled = manager.isEnabled
        let ownsProvider = previousProvider?.providerBundleIdentifier == extensionIdentifier

        do {
            if ownsProvider {
                try await remove(manager)
                try await load(manager)
                guard manager.providerProtocol?.providerBundleIdentifier != extensionIdentifier else {
                    throw EnrollmentError.configurationDidNotPersist
                }
            }
            let installed = try await SystemExtensionRequest.properties(for: extensionIdentifier)
            if !installed.isEmpty {
                _ = try await SystemExtensionRequest.submit(
                    .deactivationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
                )
                let remaining = try await SystemExtensionRequest.properties(for: extensionIdentifier)
                guard remaining.isEmpty else { throw EnrollmentError.extensionStillInstalled }
            }
            state = .inactive
        } catch {
            if ownsProvider {
                manager.providerProtocol = previousProvider
                manager.localizedDescription = previousDescription
                manager.isEnabled = previousEnabled
                try? await save(manager)
            }
            state = .failed(Self.safeMessage(for: error))
            throw error
        }
    }

    private static func safeMessage(for error: Error) -> String {
        if let error = error as? EnrollmentError {
            switch error {
            case .configurationDidNotPersist:
                return "DNS Proxy 配置未能保存或复核"
            case .bundleIdentifierUnavailable:
                return "无法读取 DNS 扩展标识，未执行卸载"
            case .extensionStillInstalled:
                return "macOS 尚未完成 DNS 扩展撤销，安装组件已保留"
            }
        }
        let nsError = error as NSError
        if nsError.domain == OSSystemExtensionErrorDomain {
            return "System Extension 未能完成撤销（\(nsError.code)）；安装组件已保留"
        }
        return "DNS Proxy 撤销失败；安装组件已保留"
    }

    private func load(_ manager: NEDNSProxyManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: ()) }
            }
        }
    }

    private func save(_ manager: NEDNSProxyManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: ()) }
            }
        }
    }

    private func remove(_ manager: NEDNSProxyManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.removeFromPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: ()) }
            }
        }
    }

    private enum EnrollmentError: Error {
        case configurationDidNotPersist
        case bundleIdentifierUnavailable
        case extensionStillInstalled
    }
}

private enum SystemExtensionRequest {
    nonisolated(unsafe) private static var associationKey: UInt8 = 0

    static func submit(_ request: OSSystemExtensionRequest) async throws -> [OSSystemExtensionProperties] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[OSSystemExtensionProperties], Error>) in
            let delegate = RequestDelegate(continuation: continuation)
            request.delegate = delegate
            objc_setAssociatedObject(request, &associationKey, delegate, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    static func properties(for identifier: String) async throws -> [OSSystemExtensionProperties] {
        let request = OSSystemExtensionRequest.propertiesRequest(
            forExtensionWithIdentifier: identifier, queue: .main)
        return try await submit(request)
    }

    private final class RequestDelegate: NSObject, OSSystemExtensionRequestDelegate, @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<[OSSystemExtensionProperties], Error>?
        private var properties: [OSSystemExtensionProperties] = []

        init(continuation: CheckedContinuation<[OSSystemExtensionProperties], Error>) {
            self.continuation = continuation
        }

        func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
            // macOS presents the approval flow. Keep the continuation pending
            // until the request completes or fails.
        }

        func request(_ request: OSSystemExtensionRequest,
                     didFinishWithResult result: OSSystemExtensionRequest.Result) {
            finish(result == .completed ? nil : RequestError.rebootRequired)
        }

        func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
            finish(error)
        }

        func request(_ request: OSSystemExtensionRequest,
                     actionForReplacingExtension existing: OSSystemExtensionProperties,
                     withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
            .replace
        }

        func request(_ request: OSSystemExtensionRequest,
                     foundProperties properties: [OSSystemExtensionProperties]) {
            lock.lock()
            self.properties = properties
            lock.unlock()
        }

        private func finish(_ error: Error?) {
            lock.lock()
            let pending = continuation
            let properties = self.properties
            continuation = nil
            lock.unlock()
            guard let pending else { return }
            if let error { pending.resume(throwing: error) }
            else { pending.resume(returning: properties) }
        }
    }

    private enum RequestError: Error {
        case rebootRequired
    }
}
