import Darwin
import Foundation

public enum ProcessExecutionError: Error, Equatable {
    case invalidExecutable
    case allocationFailed
    case execFailed(Int32)
}

/// Replaces the current process in place, preserving PID, environment, cwd,
/// file descriptors, stdin, stdout and stderr. Arguments are never shell-parsed.
public enum ProcessExecution {
    public static func replace(executable: String, arguments: [String]) throws -> Never {
        guard executable.hasPrefix("/"), !executable.utf8.contains(0),
              !arguments.contains(where: { $0.utf8.contains(0) }) else {
            throw ProcessExecutionError.invalidExecutable
        }
        var allocated: [UnsafeMutablePointer<CChar>] = []
        defer { allocated.forEach { free($0) } }
        for argument in [executable] + arguments {
            guard let pointer = strdup(argument) else { throw ProcessExecutionError.allocationFailed }
            allocated.append(pointer)
        }
        var argv: [UnsafeMutablePointer<CChar>?] = allocated.map(Optional.some)
        argv.append(nil)
        let result = executable.withCString { path in
            argv.withUnsafeMutableBufferPointer { buffer in
                Darwin.execv(path, buffer.baseAddress!)
            }
        }
        if result == -1 { throw ProcessExecutionError.execFailed(errno) }
        fatalError("execv unexpectedly returned")
    }
}
