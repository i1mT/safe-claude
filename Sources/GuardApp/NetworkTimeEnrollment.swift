import CryptoKit
import Foundation
import ServiceManagement
import GuardCore

@MainActor
final class NetworkTimeEnrollment: ObservableObject {
    enum State: Equatable {
        case checking
        case notRegistered
        case enabled(NetworkTimeStatusSnapshot?)
        case approvalRequired
        case unavailable
        case failed
    }

    @Published private(set) var state: State = .checking
    private let service = SMAppService.daemon(plistName: "local.safeclaude.time-status.plist")
    private let registrationFingerprintKey = "networkTimeStatusServiceFingerprint"
    private var updatingRegistration = false
    var serviceIsRegistered: Bool {
        switch service.status {
        case .enabled, .requiresApproval: return true
        default: return false
        }
    }

    func refresh() {
        guard let fingerprint = registrationFingerprint() else {
            state = .unavailable
            return
        }
        switch service.status {
        case .enabled:
            if UserDefaults.standard.string(forKey: registrationFingerprintKey) != fingerprint {
                refreshRegistration(for: fingerprint)
                return
            }
            state = .enabled(NetworkTimeStatus.read())
        case .requiresApproval:
            if UserDefaults.standard.string(forKey: registrationFingerprintKey) != fingerprint {
                refreshRegistration(for: fingerprint)
            } else {
                state = .approvalRequired
            }
        case .notRegistered:
            state = .notRegistered
        case .notFound:
            state = .unavailable
        @unknown default:
            state = .unavailable
        }
    }

    func enable() {
        do {
            try service.register()
            guard let fingerprint = registrationFingerprint() else {
                state = .unavailable
                return
            }
            UserDefaults.standard.set(fingerprint, forKey: registrationFingerprintKey)
            refresh()
        } catch {
            state = .failed
        }
    }

    private func refreshRegistration(for fingerprint: String) {
        guard !updatingRegistration else { return }
        updatingRegistration = true
        state = .checking
        Task {
            do {
                try await service.unregister()
                try service.register()
                UserDefaults.standard.set(fingerprint, forKey: registrationFingerprintKey)
                refresh()
            } catch {
                state = .failed
            }
            updatingRegistration = false
        }
    }

    private func registrationFingerprint() -> String? {
        let contents = Bundle.main.bundleURL.appendingPathComponent("Contents", isDirectory: true)
        let files = [
            contents.appendingPathComponent("Library/LaunchDaemons/local.safeclaude.time-status.plist"),
            contents.appendingPathComponent("Library/PrivilegedHelperTools/safe-claude-time-status"),
        ]
        var hasher = SHA256()
        for file in files {
            guard let data = try? Data(contentsOf: file), !data.isEmpty else { return nil }
            var size = UInt64(data.count).bigEndian
            hasher.update(data: withUnsafeBytes(of: &size) { Data($0) })
            hasher.update(data: data)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    func disable() {
        Task {
            do {
                try await unregisterForUninstall()
            } catch {
                state = .failed
            }
        }
    }

    func unregisterForUninstall() async throws {
        let status = service.status
        let samplerStopped: Bool
        switch status {
        case .notRegistered:
            if FileManager.default.fileExists(atPath: NetworkTimeStatus.path) {
                throw EnrollmentError.snapshotServiceUnavailable
            }
            state = .notRegistered
            UserDefaults.standard.removeObject(forKey: registrationFingerprintKey)
            return
        case .enabled:
            guard await NetworkTimeStatusService.send(.prepareForUninstall) else {
                _ = await NetworkTimeStatusService.send(.resumeMonitoring)
                throw EnrollmentError.snapshotRemovalFailed
            }
            guard !FileManager.default.fileExists(atPath: NetworkTimeStatus.path) else {
                _ = await NetworkTimeStatusService.send(.resumeMonitoring)
                throw EnrollmentError.snapshotRemovalFailed
            }
            samplerStopped = true
        case .requiresApproval:
            if FileManager.default.fileExists(atPath: NetworkTimeStatus.path) {
                throw EnrollmentError.snapshotServiceUnavailable
            }
            samplerStopped = false
        case .notFound:
            throw EnrollmentError.serviceDefinitionUnavailable
        @unknown default:
            throw EnrollmentError.unknownServiceState
        }

        do {
            try await service.unregister()
            guard service.status == .notRegistered else {
                throw EnrollmentError.serviceStillRegistered
            }
        } catch {
            if samplerStopped {
                _ = await NetworkTimeStatusService.send(.resumeMonitoring)
            }
            throw error
        }
        UserDefaults.standard.removeObject(forKey: registrationFingerprintKey)
        state = .notRegistered
    }

    private enum EnrollmentError: Error {
        case serviceDefinitionUnavailable
        case unknownServiceState
        case serviceStillRegistered
        case snapshotServiceUnavailable
        case snapshotRemovalFailed
    }
}
