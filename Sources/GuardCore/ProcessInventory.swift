import Darwin
import Foundation

/// Detects positive evidence of a same-user executable outside the journal.
/// A negative result is not proof that all possible Claude entry points have
/// been discovered, so callers must not use it to mark coverage complete.
public enum ProcessInventory {
    public static func hasUnmanaged(executable: String, managed: [SessionRecord]) -> Bool? {
        unmanaged(executable: executable, managed: managed).map { !$0.isEmpty }
    }
    public static func unmanaged(executable: String, managed: [SessionRecord]) -> [ProcessIdentity]? {
        guard executable.hasPrefix("/"), !executable.utf8.contains(0) else { return nil }
        let estimate = proc_listallpids(nil, 0)
        guard estimate > 0, estimate < 1_000_000 else { return nil }
        var pids = [pid_t](repeating: 0, count: Int(estimate) + 256)
        let count = pids.withUnsafeMutableBytes { bytes in
            proc_listallpids(bytes.baseAddress, Int32(bytes.count))
        }
        guard count >= 0, count < pids.count else { return nil }
        let target = URL(fileURLWithPath: executable).resolvingSymlinksInPath().path
        var found: [ProcessIdentity] = []
        for pid in pids.prefix(Int(count)) where pid > 1 {
            guard let identity = ProcessIdentity.read(pid, ownedBy: getuid()),
                  URL(fileURLWithPath: identity.executable).resolvingSymlinksInPath().path == target else { continue }
            if !managed.contains(where: { $0.matchesProcess(identity) }) {
                found.append(identity)
                if found.count == 128 { break }
            }
        }
        return found
    }

    /// Positive evidence of a second Claude installation running for this
    /// user. A negative result stays unknown because macOS may hide process
    /// identities during exit or permission transitions.
    public static func hasOtherClaudeInstallation(excluding executable: String) -> Bool? {
        guard executable.hasPrefix("/"), !executable.utf8.contains(0) else { return nil }
        let estimate = proc_listallpids(nil, 0)
        guard estimate > 0, estimate < 1_000_000 else { return nil }
        var pids = [pid_t](repeating: 0, count: Int(estimate) + 256)
        let count = pids.withUnsafeMutableBytes { bytes in
            proc_listallpids(bytes.baseAddress, Int32(bytes.count))
        }
        guard count >= 0, count < pids.count else { return nil }
        let selected = URL(fileURLWithPath: executable).resolvingSymlinksInPath().path
        var complete = true
        var candidates: [String] = []
        for pid in pids.prefix(Int(count)) where pid > 1 {
            var info = proc_bsdinfo()
            let infoLength = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info,
                                          Int32(MemoryLayout<proc_bsdinfo>.size))
            guard infoLength == MemoryLayout<proc_bsdinfo>.size else {
                if kill(pid, 0) == 0 || errno != ESRCH { complete = false }
                continue
            }
            guard info.pbi_uid == getuid() else { continue }
            var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
            guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else {
                if kill(pid, 0) == 0 || errno != ESRCH { complete = false }
                continue
            }
            let rawPath = String(decoding: buffer.prefix(while: { $0 != 0 }).map {
                UInt8(bitPattern: $0)
            }, as: UTF8.self)
            candidates.append(rawPath)
        }
        return classifyClaudeInstallations(excluding: selected, candidatePaths: candidates,
                                           complete: complete)
    }

    static func classifyClaudeInstallations(excluding selectedExecutable: String,
                                            candidatePaths: [String], complete: Bool) -> Bool? {
        let selected = URL(fileURLWithPath: selectedExecutable).resolvingSymlinksInPath().path
        if candidatePaths.contains(where: { rawPath in
            let path = URL(fileURLWithPath: rawPath).resolvingSymlinksInPath().path
            return URL(fileURLWithPath: path).lastPathComponent == "claude" && path != selected
        }) {
            return true
        }
        return complete ? false : nil
    }
}
