import Foundation

public enum NetworkTimeStatusService {
    public static let machServiceName = "local.safeclaude.time-status"

    public enum Request: Sendable {
        case prepareForUninstall
        case resumeMonitoring
    }

    public static func send(_ request: Request, timeout: TimeInterval = 10) async -> Bool {
        guard (1...20).contains(timeout) else { return false }
        return await Task.detached(priority: .utility) {
            let connection = NSXPCConnection(
                machServiceName: machServiceName, options: [.privileged])
            connection.remoteObjectInterface = NSXPCInterface(
                with: NetworkTimeStatusServiceProtocol.self)
            let state = XPCReplyState()
            connection.interruptionHandler = { state.complete(false) }
            connection.invalidationHandler = { state.complete(false) }
            connection.resume()
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                state.complete(false)
            }) as? NetworkTimeStatusServiceProtocol else {
                connection.invalidate()
                return false
            }
            switch request {
            case .prepareForUninstall:
                proxy.prepareForUninstall { state.complete($0) }
            case .resumeMonitoring:
                proxy.resumeMonitoring { state.complete($0) }
            }
            let result = state.wait(timeout: timeout)
            connection.invalidate()
            return result
        }.value
    }
}

@objc public protocol NetworkTimeStatusServiceProtocol {
    func prepareForUninstall(reply: @escaping (Bool) -> Void)
    func resumeMonitoring(reply: @escaping (Bool) -> Void)
}

private final class XPCReplyState: @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var finished = false
    private var result = false

    func complete(_ value: Bool) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        result = value
        lock.unlock()
        semaphore.signal()
    }

    func wait(timeout: TimeInterval) -> Bool {
        guard semaphore.wait(timeout: .now() + timeout) == .success else { return false }
        lock.lock()
        defer { lock.unlock() }
        return finished && result
    }
}
