import Darwin
import Foundation

/// PID alone is not an identity: start time and executable are checked again
/// immediately before any signal.
public struct ProcessIdentity: Equatable, Sendable {
    public let pid: pid_t
    public let uid: uid_t
    public let startSeconds: UInt64
    public let startMicroseconds: UInt64
    public let executable: String

    public static func read(_ pid: pid_t, ownedBy expectedUID: uid_t? = nil) -> ProcessIdentity? {
        guard pid > 1 else { return nil }
        var info = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size else { return nil }
        guard expectedUID == nil || info.pbi_uid == expectedUID else { return nil }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        let executable = String(decoding: path.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return ProcessIdentity(pid: pid, uid: info.pbi_uid, startSeconds: info.pbi_start_tvsec,
            startMicroseconds: info.pbi_start_tvusec, executable: executable)
    }
    public func stillMatches() -> Bool { Self.read(pid) == self && uid == getuid() }
    public func sameProcess(as other: ProcessIdentity) -> Bool {
        pid == other.pid && uid == other.uid && startSeconds == other.startSeconds &&
            startMicroseconds == other.startMicroseconds
    }
    public static func parentPID(of pid: pid_t) -> pid_t? {
        guard pid > 1 else { return nil }
        var info = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) ==
                MemoryLayout<proc_bsdinfo>.size else { return nil }
        return pid_t(info.pbi_ppid)
    }
    @discardableResult public func signal(_ value: Int32) -> Bool {
        guard stillMatches() else { return false }
        return Darwin.kill(pid, value) == 0
    }
}
