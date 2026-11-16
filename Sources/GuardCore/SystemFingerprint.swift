import CryptoKit
import Darwin
import Foundation
import SystemConfiguration

/// In-memory change detector; proxy configuration is never returned or stored.
public struct SystemFingerprint: Sendable {
    private let key: SymmetricKey
    public init() {
        key = SymmetricKey(size: .bits256)
    }
    /// Uses a device-local secret when route fingerprints must remain
    /// comparable across Agent restarts. The key is never serialized.
    public init(keyData: Data) throws {
        guard keyData.count == 32 else { throw GuardIPCError.invalidMessage }
        key = SymmetricKey(data: keyData)
    }
    private func canonical(_ value: Any) -> Any? {
        if let dictionary = value as? [String: Any] {
            var pairs: [[Any]] = []
            for key in dictionary.keys.sorted() {
                guard let raw = dictionary[key], let child = canonical(raw) else { return nil }
                pairs.append([key, child])
            }
            return ["dictionary", pairs]
        }
        if let array = value as? [Any] {
            var result: [Any] = []
            for item in array { guard let child = canonical(item) else { return nil }; result.append(child) }
            return ["array", result]
        }
        if value is String || value is NSNumber || value is Data || value is Date { return value }
        return nil
    }
    func digest(_ value: Any) -> Data? {
        guard let normalized = canonical(value),
              let bytes = try? PropertyListSerialization.data(fromPropertyList: normalized, format: .binary, options: 0) else { return nil }
        return Data(HMAC<SHA256>.authenticationCode(for: bytes, using: key))
    }
    private func activeDNSConfiguration() -> [String: Any]? {
        guard let store = SCDynamicStoreCreate(nil, "SafeClaude-DNS-Snapshot" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(
                store, "State:/Network/(Global|Service/.+)/DNS" as CFString
              ) as? [String],
              !keys.isEmpty, keys.count <= 128,
              let values = SCDynamicStoreCopyMultiple(store, keys as CFArray, nil) as? [String: Any],
              values.count == keys.count,
              Set(values.keys) == Set(keys) else { return nil }
        return values
    }
    /// Returns opaque identifiers for the resolver endpoints published by the
    /// active SystemConfiguration DNS services. Raw server addresses remain
    /// transient and are never returned to the caller.
    public func activeDNSResolverDigests() -> Set<String>? {
        guard let configuration = activeDNSConfiguration() else { return nil }
        return Self.resolverDigests(in: configuration)
    }

    public func activeDNSResolvers() -> [DNSResolverEndpoint]? {
        guard let configuration = activeDNSConfiguration() else { return nil }
        return Self.resolvers(in: configuration)
    }

    static func resolverDigests(in configuration: [String: Any]) -> Set<String>? {
        guard let resolvers = resolvers(in: configuration), !resolvers.isEmpty else { return nil }
        return Set(resolvers.map(\.digest))
    }

    static func resolvers(in configuration: [String: Any]) -> [DNSResolverEndpoint]? {
        guard !configuration.isEmpty, configuration.count <= 128 else { return nil }
        var resolvers: [DNSResolverEndpoint] = []
        var seen: [String: DNSResolverEndpoint] = [:]
        var addressCount = 0
        for value in configuration.values {
            guard let service = value as? [String: Any] else { return nil }
            guard let rawAddresses = service["ServerAddresses"] else { continue }
            guard let addresses = rawAddresses as? [String], !addresses.isEmpty,
                  addresses.count <= 64 else { return nil }
            let port: UInt16
            if let rawPort = service["ServerPort"] {
                guard let number = rawPort as? NSNumber, (1...65_535).contains(number.intValue) else {
                    return nil
                }
                port = UInt16(number.intValue)
            } else {
                port = 53
            }
            let tlsServerName: String?
            if let rawName = service["ServerName"] {
                guard let name = rawName as? String else { return nil }
                tlsServerName = name
            } else {
                tlsServerName = nil
            }
            addressCount += addresses.count
            guard addressCount <= 512 else { return nil }
            for address in addresses {
                guard let endpoint = DNSResolverEndpoint(host: address, port: port,
                                                        tlsServerName: tlsServerName) else {
                    return nil
                }
                if let existing = seen[endpoint.digest] {
                    guard existing.tlsServerName == endpoint.tlsServerName else { return nil }
                } else {
                    seen[endpoint.digest] = endpoint
                    resolvers.append(endpoint)
                }
            }
        }
        return resolvers.isEmpty ? nil : resolvers
    }
    /// A keyed in-memory digest of active resolver configuration. Raw DNS
    /// addresses, search domains and service identifiers are never returned.
    func routeConfigurationDigest(proxies: [String: Any], dns: [String: Any]) -> Data? {
        digest(["proxies": proxies, "dns": dns])
    }
    public func captureRouteConfiguration() -> Data? {
        guard let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any],
              let dns = activeDNSConfiguration() else { return nil }
        return routeConfigurationDigest(proxies: proxies, dns: dns)
    }
    public func capture() -> Data? {
        guard let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any],
              let dns = activeDNSConfiguration() else { return nil }
        let snapshot = LocalEnvironmentSnapshot.capture()
        let values: [Any] = [proxies, dns, snapshot.systemTimeZoneIdentifier ?? "",
                             snapshot.systemLocaleIdentifier ?? "", snapshot.preferredLanguages]
        return digest(values)
    }
    public func captureLocale() -> Data? {
        let snapshot = LocalEnvironmentSnapshot.capture()
        guard let zone = snapshot.systemTimeZoneIdentifier, let locale = snapshot.systemLocaleIdentifier,
              !snapshot.preferredLanguages.isEmpty else { return nil }
        return digest([zone, locale, snapshot.preferredLanguages])
    }
    /// Hash only file metadata. Configuration values, including unrelated
    /// secrets, do not enter this change detector.
    public func captureSettings(paths: [String]) -> Data? {
        guard paths.count <= 64 else { return nil }
        var values: [[String: Any]] = []
        for path in paths.sorted() {
            guard path.hasPrefix("/"), path.utf8.count <= 8192, !path.utf8.contains(0) else { return nil }
            var info = stat()
            if lstat(path, &info) != 0 {
                guard errno == ENOENT else { return nil }
                values.append(["path": path, "absent": true])
                continue
            }
            if (info.st_mode & S_IFMT) == S_IFDIR {
                let directoryFD = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
                guard directoryFD >= 0 else { return nil }
                defer { close(directoryFD) }
                var openedDirectory = stat()
                guard fstat(directoryFD, &openedDirectory) == 0,
                      openedDirectory.st_dev == info.st_dev,
                      openedDirectory.st_ino == info.st_ino else { return nil }
                guard let names = try? FileManager.default.contentsOfDirectory(atPath: path),
                      names.count <= 128 else { return nil }
                var entries: [[String: Any]] = []
                for name in names.sorted() {
                    guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
                          name.utf8.count <= 255 else { return nil }
                    var childInfo = stat()
                    let childPath = URL(fileURLWithPath: path).appendingPathComponent(name).path
                    guard lstat(childPath, &childInfo) == 0,
                          (childInfo.st_mode & S_IFMT) == S_IFREG else { return nil }
                    let childFD = open(childPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
                    guard childFD >= 0 else { return nil }
                    var openedChild = stat()
                    let childValid = fstat(childFD, &openedChild) == 0 &&
                        (openedChild.st_mode & S_IFMT) == S_IFREG &&
                        openedChild.st_dev == childInfo.st_dev && openedChild.st_ino == childInfo.st_ino &&
                        openedChild.st_size == childInfo.st_size &&
                        openedChild.st_mtimespec.tv_sec == childInfo.st_mtimespec.tv_sec &&
                        openedChild.st_mtimespec.tv_nsec == childInfo.st_mtimespec.tv_nsec &&
                        openedChild.st_ctimespec.tv_sec == childInfo.st_ctimespec.tv_sec &&
                        openedChild.st_ctimespec.tv_nsec == childInfo.st_ctimespec.tv_nsec
                    close(childFD)
                    guard childValid else { return nil }
                    entries.append(["name": name, "device": Int64(childInfo.st_dev),
                                    "inode": UInt64(childInfo.st_ino), "mode": Int64(childInfo.st_mode),
                                    "size": childInfo.st_size,
                                    "mtimeSec": childInfo.st_mtimespec.tv_sec,
                                    "mtimeNsec": childInfo.st_mtimespec.tv_nsec,
                                    "ctimeSec": childInfo.st_ctimespec.tv_sec,
                                    "ctimeNsec": childInfo.st_ctimespec.tv_nsec])
                }
                var finalDirectory = stat()
                var finalPath = stat()
                guard fstat(directoryFD, &finalDirectory) == 0,
                      lstat(path, &finalPath) == 0,
                      finalPath.st_dev == openedDirectory.st_dev,
                      finalPath.st_ino == openedDirectory.st_ino,
                      finalDirectory.st_mtimespec.tv_sec == openedDirectory.st_mtimespec.tv_sec,
                      finalDirectory.st_mtimespec.tv_nsec == openedDirectory.st_mtimespec.tv_nsec,
                      finalDirectory.st_ctimespec.tv_sec == openedDirectory.st_ctimespec.tv_sec,
                      finalDirectory.st_ctimespec.tv_nsec == openedDirectory.st_ctimespec.tv_nsec else { return nil }
                values.append(["path": path, "directory": entries,
                               "device": Int64(openedDirectory.st_dev), "inode": UInt64(openedDirectory.st_ino),
                               "mtimeSec": openedDirectory.st_mtimespec.tv_sec,
                               "mtimeNsec": openedDirectory.st_mtimespec.tv_nsec,
                               "ctimeSec": openedDirectory.st_ctimespec.tv_sec,
                               "ctimeNsec": openedDirectory.st_ctimespec.tv_nsec])
                continue
            }
            guard (info.st_mode & S_IFMT) == S_IFREG else { return nil }
            let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            guard fd >= 0 else { return nil }
            var opened = stat()
            let valid = fstat(fd, &opened) == 0 && (opened.st_mode & S_IFMT) == S_IFREG &&
                opened.st_dev == info.st_dev && opened.st_ino == info.st_ino &&
                opened.st_size == info.st_size &&
                opened.st_mtimespec.tv_sec == info.st_mtimespec.tv_sec &&
                opened.st_mtimespec.tv_nsec == info.st_mtimespec.tv_nsec &&
                opened.st_ctimespec.tv_sec == info.st_ctimespec.tv_sec &&
                opened.st_ctimespec.tv_nsec == info.st_ctimespec.tv_nsec
            close(fd)
            guard valid else { return nil }
            values.append(["path": path, "device": Int64(info.st_dev), "inode": UInt64(info.st_ino),
                           "mode": Int64(info.st_mode), "size": info.st_size,
                           "mtimeSec": info.st_mtimespec.tv_sec, "mtimeNsec": info.st_mtimespec.tv_nsec,
                           "ctimeSec": info.st_ctimespec.tv_sec, "ctimeNsec": info.st_ctimespec.tv_nsec])
        }
        let preferences = SelectiveSettings.inspectManagedPreferences()
        let locale = preferences.locale.keys.sorted().map { [$0, preferences.locale[$0]!] }
        values.append(["managedPreferencesSignals": [
            "routingOverride": preferences.routingOverride,
            "customEndpoint": preferences.customEndpoint,
            "tlsDisabled": preferences.tlsDisabled,
            "locale": locale,
            "invalidLocaleKeys": preferences.invalidLocaleKeys.sorted()
        ]])
        return digest(values)
    }
}
