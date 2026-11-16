import Darwin
import Foundation
import Security

public enum ClientCertificateStatus: String, Codable, Equatable, Hashable, Sendable {
    case valid, expiring, expired
}

/// Reads only the first PEM certificate block and stops before any following
/// private key. Unknown formats and paths remain unverified.
public enum ClientCertificate {
    public static func inspect(path: String, at now: Date = Date()) -> ClientCertificateStatus? {
        guard path.hasPrefix("/"), path.utf8.count <= 4096, !path.utf8.contains(0) else { return nil }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              (1...4_194_304).contains(info.st_size) else { return nil }
        var consumed = 0
        func readByte() -> UInt8? {
            guard consumed < 65_536 else { return nil }
            while true {
                var byte: UInt8 = 0
                let count = Darwin.read(fd, &byte, 1)
                if count < 0 && errno == EINTR { continue }
                guard count == 1 else { return nil }
                consumed += 1
                return byte
            }
        }
        // Reject a private key or binary input as soon as its prefix differs;
        // do not read ahead into an unknown PEM/DER block.
        for expected in "-----BEGIN CERTIFICATE-----".utf8 {
            guard readByte() == expected else { return nil }
        }
        guard let newline = readByte() else { return nil }
        if newline == 13 {
            guard readByte() == 10 else { return nil }
        } else if newline != 10 { return nil }
        func line() -> String? {
            var data = [UInt8]()
            while consumed < 65_536 && data.count <= 128 {
                guard let byte = readByte() else {
                    return data.isEmpty ? nil : String(bytes: data, encoding: .ascii)
                }
                if byte == 10 { return String(bytes: data, encoding: .ascii) }
                if byte != 13 { data.append(byte) }
            }
            return nil
        }
        var encoded = ""
        var ended = false
        while let next = line() {
            if next == "-----END CERTIFICATE-----" { ended = true; break }
            guard !next.isEmpty, next.utf8.allSatisfy({
                (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) ||
                $0 == 43 || $0 == 47 || $0 == 61
            }) else { return nil }
            encoded += next
        }
        guard ended, let data = Data(base64Encoded: encoded),
              let certificate = SecCertificateCreateWithData(nil, data as CFData),
              let values = SecCertificateCopyValues(certificate, [kSecOIDX509V1ValidityNotAfter] as CFArray, nil)
                as? [String: Any],
              let property = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any],
              let raw = property[kSecPropertyKeyValue as String] as? NSNumber,
              CFGetTypeID(raw) != CFBooleanGetTypeID(), raw.doubleValue.isFinite else { return nil }
        let remaining = Date(timeIntervalSinceReferenceDate: raw.doubleValue).timeIntervalSince(now)
        if remaining <= 0 { return .expired }
        if remaining <= 86_400 { return .expiring }
        return .valid
    }
}
