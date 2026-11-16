import Foundation

@main
struct GeoRuntimeDriver {
    static func main() async {
        let keys = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy",
                    "NO_PROXY", "no_proxy", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE", "SSL_CERT_DIR"]
        var environment: [String: String] = [:]
        for key in keys {
            if let value = getenv(key) { environment[key] = String(cString: value) }
        }
        guard case .observed(let trace) = TraceProbe.observe(.api, environment: environment) else {
            print("{\"trace\":false}")
            exit(1)
        }
        do {
            let result = try await IPWhoGeolocation.fetch(ip: trace.ip, routingEnvironment: environment)
            let output: [String: Any] = ["trace": true, "geo": true, "country": result.countryCode != nil,
                                         "timezone": result.timeZone != nil, "asn": result.autonomousSystem != nil]
            let bytes = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
            FileHandle.standardOutput.write(bytes)
            FileHandle.standardOutput.write(Data("\n".utf8))
        } catch {
            print("{\"trace\":true,\"geo\":false}")
            exit(1)
        }
    }
}
