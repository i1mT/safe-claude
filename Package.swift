// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "SafeClaude",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "GuardCore", targets: ["GuardCore"]),
        .library(name: "AgentSupervisorSupport", targets: ["AgentSupervisorSupport"]),
        .executable(name: "safe-claude", targets: ["GuardCLI"]),
        .executable(name: "safe-claude-agent", targets: ["GuardAgent"]),
        .executable(name: "safe-claude-time-status", targets: ["GuardTimeStatus"]),
        .executable(name: "SafeClaudeApp", targets: ["GuardApp"]),
    ],
    targets: [
        .target(name: "GuardCore", resources: [.process("Resources")]),
        .target(name: "AgentSupervisorSupport", dependencies: ["GuardCore"]),
        .executableTarget(name: "GuardCLI", dependencies: ["GuardCore"]),
        .executableTarget(name: "GuardAgent", dependencies: ["GuardCore"],
                          exclude: ["SafeClaudeAgent.entitlements"]),
        .executableTarget(name: "GuardTimeStatus", dependencies: ["GuardCore"]),
        .executableTarget(name: "GuardApp", dependencies: ["GuardCore", "AgentSupervisorSupport"],
                          exclude: ["SafeClaudeApp.entitlements", "local.safeclaude.time-status.plist"]),
        .testTarget(name: "GuardCoreTests", dependencies: ["GuardCore", "AgentSupervisorSupport"],
                    resources: [.process("Fixtures")]),
    ]
)
