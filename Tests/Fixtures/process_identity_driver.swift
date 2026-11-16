import Darwin
import Foundation

guard CommandLine.arguments.count == 2, let pid = pid_t(CommandLine.arguments[1]) else {
    exit(64)
}
var info = proc_bsdinfo()
guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) ==
        MemoryLayout<proc_bsdinfo>.size else {
    exit(1)
}
var path = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { exit(1) }
let executable = String(decoding: path.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
let result: [String: Any] = [
    "pid": Int(pid),
    "uid": Int(info.pbi_uid),
    "startSeconds": UInt64(info.pbi_start_tvsec),
    "startMicroseconds": UInt64(info.pbi_start_tvusec),
    "executable": executable,
]
let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
FileHandle.standardOutput.write(data)
FileHandle.standardOutput.write(Data("\n".utf8))
