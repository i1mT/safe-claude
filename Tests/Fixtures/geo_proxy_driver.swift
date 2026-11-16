import Foundation

@main
struct GeoProxyDriver {
    static func main() throws {
        let object = try JSONSerialization.jsonObject(with: FileHandle.standardInput.readDataToEndOfFile()) as! [String: String]
        let url = try IPWhoGeolocation.request(ip: "192.0.2.42").url!
        let data = try GeolocationTransport.get(url: url,
            environment: ["HTTPS_PROXY": object["proxy"]!, "NO_PROXY": object["no_proxy"]!],
            executable: URL(fileURLWithPath: object["curl_wrapper"]!))
        let result = try IPWhoGeolocation.decode(data, expectedIP: "192.0.2.42")
        print(result.countryCode == "US" ? "ok" : "invalid")
    }
}
