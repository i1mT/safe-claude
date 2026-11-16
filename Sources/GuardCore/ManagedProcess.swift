import Darwin
import Foundation

public enum ManagedProcess {
    /// Find only a registered ancestor whose complete current image identity
    /// matches the journal; never infer ownership from a name alone.
    public static func ancestor(of child: ProcessIdentity, records: [SessionRecord]) -> ProcessIdentity? {
        var current = child
        var seen = Set<pid_t>()
        for _ in 0..<16 {
            guard current.stillMatches(), let parent = ProcessIdentity.parentPID(of: current.pid),
                  parent > 1, seen.insert(parent).inserted, let identity = ProcessIdentity.read(parent),
                  identity.uid == getuid() else { return nil }
            current = identity
            if records.contains(where: { $0.matches(identity) }) { return identity }
        }
        return nil
    }

    /// Re-read identity before every signal, including after exec transitions.
    public static func terminate(_ start: ProcessIdentity, force: Bool) async -> Bool {
        await terminate(start, force: force, gracefulDelay: 2, killDelay: 1)
    }

    static func terminate(_ start: ProcessIdentity, force: Bool,
                          gracefulDelay: Double, killDelay: Double) async -> Bool {
        func current() -> ProcessIdentity? {
            guard let value = ProcessIdentity.read(start.pid), value.sameProcess(as: start) else { return nil }
            return value
        }
        func exited() -> Bool {
            if let value = ProcessIdentity.read(start.pid) { return !value.sameProcess(as: start) }
            return kill(start.pid, 0) == -1 && errno == ESRCH
        }
        if let identity = current() { _ = identity.signal(SIGCONT); _ = identity.signal(SIGINT) }
        else { return exited() }
        try? await Task.sleep(for: .seconds(gracefulDelay))
        if let identity = current() { _ = identity.signal(SIGTERM) }
        else { return exited() }
        if force {
            try? await Task.sleep(for: .seconds(killDelay))
            if let identity = current() { _ = identity.signal(SIGKILL) }
            else { return exited() }
        }
        try? await Task.sleep(for: .seconds(killDelay))
        return exited()
    }
}
