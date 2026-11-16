import Darwin
import Foundation

enum BoundedFile {
    /// A size check before reading is insufficient: a regular file may grow
    /// concurrently. Never allocate more than the declared limit.
    static func read(_ fd: Int32, maximum: Int) throws -> Data {
        guard maximum >= 0 else { throw GuardIPCError.invalidMessage }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let remaining = maximum - result.count
            let readSize = remaining >= buffer.count ? buffer.count : remaining + 1
            let count = Darwin.read(fd, &buffer, readSize)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw GuardIPCError.system(errno) }
            if count == 0 { return result }
            guard count <= maximum - result.count else { throw GuardIPCError.invalidMessage }
            result.append(contentsOf: buffer.prefix(count))
        }
    }
}
