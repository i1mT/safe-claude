import Foundation
import Network
import NetworkExtension
import GuardCore

private func recordDNSPathEvidence(flow: NEAppProxyFlow, endpoint: NWEndpoint,
                                   transport: DNSPathEvidence.Transport, questions: [String],
                                   systemDNSSettings: [NEDNSSettings]?) {
    guard let spool = DNSPathEvidenceSpool.shared() else { return }
    guard case let .hostPort(host, port) = endpoint,
          let resolverIdentity = DNSPathEvidence.resolverIdentity(
            host: String(describing: host), port: port.rawValue
          ) else { return }
    guard let tokenData = flow.metaData.sourceAppAuditToken,
          tokenData.count == MemoryLayout<audit_token_t>.size else { return }
    let token = tokenData.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
    let pid = audit_token_to_pid(token)
    let pidVersion = audit_token_to_pidversion(token)
    guard pid > 1, pidVersion > 0,
          let identity = ProcessIdentity.read(pid, ownedBy: getuid()) else { return }
    let domains = questions.compactMap { name -> DNSPathEvidence.DomainClass? in
        guard DNSQuestionParser.isProtectedDomain(name) else { return nil }
        if name == "api.anthropic.com" || name.hasSuffix(".api.anthropic.com") {
            return .anthropicAPI
        }
        return .claudeWeb
    }
    for domain in Set(domains) {
        let names = questions.filter { name in
            guard DNSQuestionParser.isProtectedDomain(name) else { return false }
            if domain == .anthropicAPI {
                return name == "api.anthropic.com" || name.hasSuffix(".api.anthropic.com")
            }
            return name != "api.anthropic.com" && !name.hasSuffix(".api.anthropic.com")
        }
        let security = resolverSecurity(settings: systemDNSSettings, queryNames: names)
        let item = DNSPathEvidence(pid: pid, pidVersion: pidVersion,
            processStartSeconds: identity.startSeconds,
            processStartMicroseconds: identity.startMicroseconds,
            domainClass: domain, transport: transport,
            resolverIdentity: resolverIdentity, resolverSecurity: security)
        try? spool.append(item)
        if security == .dnsOverHTTPS {
            enrichDoHCountry(item, settings: systemDNSSettings, queryNames: names,
                             observedIdentity: resolverIdentity, spool: spool)
        }
    }
}

private func resolverSecurity(settings: [NEDNSSettings]?, queryNames: [String])
    -> DNSPathEvidence.ResolverSecurity {
    let configurations = settings?.map { setting in
        let security: DNSPathEvidence.ResolverSecurity
        switch setting.dnsProtocol {
        case .TLS: security = .dnsOverTLS
        case .HTTPS: security = .dnsOverHTTPS
        case .cleartext: security = .cleartext
        @unknown default: security = .unknown
        }
        return DNSResolverPolicySetting(security: security, matchDomains: setting.matchDomains)
    }
    return DNSResolverPolicy.security(for: queryNames, settings: configurations)
}

private struct DoHServerCandidate: Sendable {
    let serverURL: URL
    let serverIP: String
    let resolverIdentity: String
}

private func matchingDoHServer(settings: [NEDNSSettings]?, queryNames: [String],
                               observedIdentity: String) -> DoHServerCandidate? {
    guard let settings, !settings.isEmpty, !queryNames.isEmpty else { return nil }
    let configurations = settings.map { setting in
        let security: DNSPathEvidence.ResolverSecurity
        switch setting.dnsProtocol {
        case .TLS: security = .dnsOverTLS
        case .HTTPS: security = .dnsOverHTTPS
        case .cleartext: security = .cleartext
        @unknown default: security = .unknown
        }
        return DNSResolverPolicySetting(security: security, matchDomains: setting.matchDomains)
    }
    guard let index = DNSResolverPolicy.uniqueApplicableSettingIndex(
        for: queryNames, settings: configurations),
          settings[index].dnsProtocol == .HTTPS,
          let setting = settings[index] as? NEDNSOverHTTPSSettings,
          setting.identityReference == nil,
          let serverURL = setting.serverURL,
          setting.servers.count <= 8,
          !setting.servers.isEmpty else { return nil }
    guard serverURL.scheme?.lowercased() == "https",
          let port = UInt16(exactly: serverURL.port ?? 443), port > 0 else { return nil }
    let matches = setting.servers.compactMap { address -> DoHServerCandidate? in
        guard DNSPathEvidence.isLiteralAddress(address),
              let identity = DNSPathEvidence.resolverIdentity(host: address, port: port),
              identity == observedIdentity else { return nil }
        return DoHServerCandidate(serverURL: serverURL, serverIP: address,
                                  resolverIdentity: identity)
    }
    return matches.count == 1 ? matches.first : nil
}

private struct DoHCountryResult: Sendable {
    let countryCode: String
    let observedAt: Date
}

private final class NoRedirectGeolocationDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

private actor DoHCountryProbeCache {
    static let shared = DoHCountryProbeCache()
    private struct Entry {
        let result: DoHCountryResult
    }
    private var entries: [String: Entry] = [:]
    private var flights: [String: Task<DoHCountryResult?, Never>] = [:]
    private var retryAfter: [String: Date] = [:]
    private let lifetime: TimeInterval = 120
    private let systemFingerprint = SystemFingerprint()

    func observe(_ candidate: DoHServerCandidate) async -> DoHCountryResult? {
        guard let route = systemFingerprint.captureRouteConfiguration() else { return nil }
        let key = DNSPathEvidence.digest(candidate.serverURL.absoluteString + "|" +
                                         candidate.serverIP + "|" + route.base64EncodedString())
        let now = Date()
        if let entry = entries[key],
           (0...lifetime).contains(now.timeIntervalSince(entry.result.observedAt)) {
            return entry.result
        }
        if retryAfter[key].map({ $0 > now }) == true { return nil }
        if let flight = flights[key] { return await flight.value }
        let flight = Task.detached(priority: .utility) { () -> DoHCountryResult? in
            guard DNSResolverProbeConsent.isAllowed,
                  let address = DNSOverHTTPSProbe.observe(serverURL: candidate.serverURL,
                                                          serverIP: candidate.serverIP),
                  DNSResolverProbeConsent.isAllowed,
                  let request = try? IPWhoGeolocation.request(ip: address) else { return nil }
            let session = URLSession(configuration: .ephemeral,
                delegate: NoRedirectGeolocationDelegate(), delegateQueue: nil)
            defer { session.invalidateAndCancel() }
            guard let (data, response) = try? await session.data(for: request),
                  data.count <= 65_536,
                  let http = response as? HTTPURLResponse, http.statusCode == 200,
                  http.url?.scheme == "https", http.url?.host == "ipwho.is",
                  let reputation = try? IPWhoGeolocation.decode(data, expectedIP: address),
                  let country = reputation.countryCode else { return nil }
            return DoHCountryResult(countryCode: country, observedAt: Date())
        }
        flights[key] = flight
        let result = await flight.value
        flights.removeValue(forKey: key)
        if let result {
            retryAfter.removeValue(forKey: key)
            entries[key] = Entry(result: result)
            if entries.count > 32,
               let oldest = entries.min(by: { $0.value.result.observedAt < $1.value.result.observedAt })?.key {
                entries.removeValue(forKey: oldest)
            }
        } else {
            retryAfter[key] = Date().addingTimeInterval(60)
            if retryAfter.count > 32,
               let oldest = retryAfter.min(by: { $0.value < $1.value })?.key {
                retryAfter.removeValue(forKey: oldest)
            }
        }
        return result
    }
}

private func enrichDoHCountry(_ evidence: DNSPathEvidence, settings: [NEDNSSettings]?,
                              queryNames: [String], observedIdentity: String,
                              spool: DNSPathEvidenceSpool) {
    guard DNSResolverProbeConsent.isAllowed,
          let candidate = matchingDoHServer(settings: settings, queryNames: queryNames,
                                             observedIdentity: observedIdentity) else { return }
    Task.detached(priority: .utility) {
        guard DNSResolverProbeConsent.isAllowed,
              let result = await DoHCountryProbeCache.shared.observe(candidate),
              DNSResolverProbeConsent.isAllowed else { return }
        let enriched = evidence.carryingResolverCountry(result.countryCode,
            resolverIdentity: candidate.resolverIdentity, observedAt: result.observedAt)
        try? spool.append(enriched)
    }
}

private final class DNSSettingsSnapshot: @unchecked Sendable {
    private let lock = NSLock()
    private var value: [NEDNSSettings]?

    func update(_ settings: [NEDNSSettings]?) {
        lock.lock()
        value = settings
        lock.unlock()
    }

    func current() -> [NEDNSSettings]? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

final class DNSProxyProvider: NEDNSProxyProvider {
    private let relayLock = NSLock()
    private var relays: [ObjectIdentifier: DNSFlowRelay] = [:]
    private let queue = DispatchQueue(label: "com.safeclaude.dnsproxy", qos: .utility)
    private let dnsSettingsSnapshot = DNSSettingsSnapshot()
    private var dnsSettingsObservation: NSKeyValueObservation?

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        dnsSettingsObservation = observe(\.systemDNSSettings, options: [.initial, .new]) {
            [weak dnsSettingsSnapshot] _, change in
            dnsSettingsSnapshot?.update(change.newValue ?? nil)
        }
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        relayLock.lock()
        let active = Array(relays.values)
        relays.removeAll()
        relayLock.unlock()
        active.forEach { $0.cancel() }
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let relay: DNSFlowRelay
        let settings = dnsSettingsSnapshot
        if let tcp = flow as? NEAppProxyTCPFlow {
            relay = DNSTCPRelay(flow: tcp, queue: queue, systemDNSSettings: settings)
        } else if let udp = flow as? NEAppProxyUDPFlow {
            relay = DNSUDPRelay(flow: udp, queue: queue, systemDNSSettings: settings)
        } else {
            return false
        }
        let key = ObjectIdentifier(flow)
        relay.onClose = { [weak self] in
            guard let self else { return }
            self.relayLock.lock()
            self.relays.removeValue(forKey: key)
            self.relayLock.unlock()
        }
        relayLock.lock()
        relays[key] = relay
        relayLock.unlock()
        relay.start()
        return true
    }
}

private protocol DNSFlowRelay: AnyObject, Sendable {
    var onClose: (() -> Void)? { get set }
    func start()
    func cancel()
}

private final class DNSUDPRelay: DNSFlowRelay, @unchecked Sendable {
    private static let maximumConcurrentQueries = 64
    private static let queryTimeout: TimeInterval = 5
    private let flow: NEAppProxyUDPFlow
    private let queue: DispatchQueue
    private let systemDNSSettings: DNSSettingsSnapshot
    private let lock = NSLock()
    private var connections: [ObjectIdentifier: NWConnection] = [:]
    private var timeouts: [ObjectIdentifier: DispatchWorkItem] = [:]
    private var stopped = false
    var onClose: (() -> Void)?

    init(flow: NEAppProxyUDPFlow, queue: DispatchQueue, systemDNSSettings: DNSSettingsSnapshot) {
        self.flow = flow
        self.queue = queue
        self.systemDNSSettings = systemDNSSettings
    }

    func start() {
        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            guard let self else { return }
            if error != nil { self.finish(error); return }
            self.readNextBatch()
        }
    }

    private func readNextBatch() {
        guard !isStopped else { return }
        flow.readDatagrams { [weak self] packets, error in
            self?.consume(packets, error: error)
        }
    }

    private func consume(_ packets: [(Data, NWEndpoint)]?, error: Error?) {
        if error != nil { finish(error); return }
        guard let packets else { finish(nil); return }
        for (packet, endpoint) in packets {
            guard !isStopped else { return }
            guard packet.count <= 65_535, Self.isDNSPort(endpoint) else {
                finish(Self.error(EPROTO))
                return
            }
            // Query names are inspected only in memory; the packet and name
            // are never logged, persisted, or sent to the containing app.
            if let questions = try? DNSQuestionParser.questions(in: packet) {
                recordDNSPathEvidence(flow: flow, endpoint: endpoint, transport: .udp,
                    questions: questions, systemDNSSettings: systemDNSSettings.current())
            }
            forward(packet, to: endpoint)
        }
        readNextBatch()
    }

    private func forward(_ packet: Data, to endpoint: NWEndpoint) {
        let connection = NWConnection(to: endpoint, using: .udp)
        let key = ObjectIdentifier(connection)
        let timeout = DispatchWorkItem { [weak self] in
            self?.finish(Self.error(ETIMEDOUT))
        }
        lock.lock()
        guard !stopped, connections.count < Self.maximumConcurrentQueries else {
            let wasOverloaded = !stopped
            lock.unlock()
            connection.cancel()
            if wasOverloaded { finish(Self.error(ENOBUFS)) }
            return
        }
        connections[key] = connection
        timeouts[key] = timeout
        lock.unlock()
        queue.asyncAfter(deadline: .now() + Self.queryTimeout, execute: timeout)

        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection else { return }
            switch state {
            case .ready:
                connection.send(content: packet, completion: .contentProcessed { error in
                    if let error { self.finish(error); return }
                    connection.receiveMessage { data, _, _, receiveError in
                        if let receiveError {
                            self.finish(receiveError)
                            return
                        }
                        guard let data, !data.isEmpty else {
                            self.finish(Self.error(ENODATA))
                            return
                        }
                        self.write(data, from: endpoint) {
                            self.remove(connection)
                        }
                    }
                })
            case .failed(let error):
                self.finish(error)
            case .cancelled:
                self.remove(connection)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    private func write(_ data: Data, from endpoint: NWEndpoint, completion: @escaping () -> Void) {
        flow.writeDatagrams([(data, endpoint)]) { [weak self] error in
            if let error { self?.finish(error) }
            else { completion() }
        }
    }

    private static func isDNSPort(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(_, port) = endpoint else { return false }
        return port == 53
    }

    private static func error(_ code: Int32) -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(code))
    }

    private var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    private func remove(_ connection: NWConnection) {
        let key = ObjectIdentifier(connection)
        lock.lock()
        let removed = connections.removeValue(forKey: key)
        let timeout = timeouts.removeValue(forKey: key)
        lock.unlock()
        timeout?.cancel()
        removed?.cancel()
    }

    private func finish(_ error: Error?) {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        stopped = true
        let active = Array(connections.values)
        let activeTimeouts = Array(timeouts.values)
        connections.removeAll()
        timeouts.removeAll()
        lock.unlock()
        activeTimeouts.forEach { $0.cancel() }
        active.forEach { $0.cancel() }
        if let error {
            flow.closeReadWithError(error as NSError)
            flow.closeWriteWithError(error as NSError)
        } else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        onClose?()
    }

    func cancel() { finish(nil) }
}

private final class DNSTCPRelay: DNSFlowRelay, @unchecked Sendable {
    private let flow: NEAppProxyTCPFlow
    private let queue: DispatchQueue
    private let systemDNSSettings: DNSSettingsSnapshot
    private let connection: NWConnection
    private let lock = NSLock()
    private var stopped = false
    private var decoder = DNSOverTCPFrameDecoder()
    var onClose: (() -> Void)?

    init(flow: NEAppProxyTCPFlow, queue: DispatchQueue, systemDNSSettings: DNSSettingsSnapshot) {
        self.flow = flow
        self.queue = queue
        self.systemDNSSettings = systemDNSSettings
        self.connection = NWConnection(to: flow.remoteFlowEndpoint, using: .tcp)
    }

    func start() {
        guard Self.isDNSPort(flow.remoteFlowEndpoint) else { finish(nil); return }
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.openFlow()
            case .failed, .cancelled:
                self.finish(nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    private func openFlow() {
        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            guard let self else { return }
            if error != nil { self.finish(error); return }
            self.readFromClient()
            self.readFromResolver()
        }
    }

    private func readFromClient() {
        guard !isStopped else { return }
        flow.readData { [weak self] data, error in
            guard let self else { return }
            if let error { self.finish(error); return }
            guard let data, !data.isEmpty else { self.finish(nil); return }
            do {
                let frames = try self.decoder.append(data)
                for questions in frames {
                recordDNSPathEvidence(flow: self.flow, endpoint: self.flow.remoteFlowEndpoint,
                    transport: .tcp, questions: questions,
                    systemDNSSettings: systemDNSSettings.current())
                }
            } catch {
                // Parsing failure removes DNS path evidence but does not alter
                // the user's DNS request or write its content to diagnostics.
            }
            self.connection.send(content: data, completion: .contentProcessed { error in
                if let error { self.finish(error) }
                else { self.readFromClient() }
            })
        }
    }

    private func readFromResolver() {
        guard !isStopped else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_535) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error { self.finish(error); return }
            if let data, !data.isEmpty {
                self.writeToFlow(data) { error in
                    if let error { self.finish(error) }
                    else if isComplete { self.finish(nil) }
                    else { self.readFromResolver() }
                }
            } else if isComplete {
                self.finish(nil)
            } else {
                self.readFromResolver()
            }
        }
    }

    private func writeToFlow(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) {
        flow.write(data, withCompletionHandler: completion)
    }

    private static func isDNSPort(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(_, port) = endpoint else { return false }
        return port == 53
    }

    private var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    private func finish(_ error: Error?) {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        stopped = true
        lock.unlock()
        connection.cancel()
        if let error {
            flow.closeReadWithError(error as NSError)
            flow.closeWriteWithError(error as NSError)
        } else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        onClose?()
    }

    func cancel() { finish(nil) }
}
