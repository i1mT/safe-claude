import Foundation

// Compiled with the real GuardCore sources into a temporary fixture executable.
@main
struct TraceProbeFixtureDriver {
    static func main() throws {
        let input = try JSONSerialization.jsonObject(with: FileHandle.standardInput.readDataToEndOfFile()) as! [String: String]
        let result = TraceProbe.execute(
            url: URL(string: input["url"]!)!,
            environment: ["https_proxy": input["proxy"]!, "no_proxy": input["no_proxy"]!],
            executable: URL(fileURLWithPath: input["curl_wrapper"]!)
        )
        let output: [String: String]
        switch result {
        case .observed(let observation):
            output = ["status": "observed", "host": observation.targetHost,
                      "ip": observation.ip, "country": observation.countryCode ?? ""]
        case .unknown(let reason):
            output = ["status": "unknown", "reason": reason]
        }
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys]))
    }
}
