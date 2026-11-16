# 阶段 04 验收记录（持续实施）

日期：2026-11-14
主机：macOS 15.6、Apple silicon、Swift 6.2；本机 Claude Code 2.1.323（启动阻断夹具使用隔离配置，不登录、不发模型请求）。

## 本轮通过

- `swift test`：183 项通过。
- `swift build -c release`：通过。
- 安装集成：隔离 HOME 下 install、upgrade、失败保护、卸载恢复、并发互斥夹具通过。
- 启动保护：Agent 全量状态与真实 Claude 阻断夹具通过；官方 `processWrapper` 子进程拒绝后精确中断受管父会话夹具通过；未受管 Claude 处置只作用于身份匹配进程。
- 网络夹具：代理 CONNECT、`NO_PROXY` 绕过、有效 settings 路由优先级、TLS 设置阻断、地理供应商代理传输与凭据脱敏通过。
- 性能：真实本机 Agent + launcher + Claude `--version` 阻断预检 10 次；全部低于 2.5 秒，p95 65.5 ms，中位数 34.8 ms。范围不含完整在线信誉供应商请求和模型请求。
- 发行结构：`Scripts/package.py` 生成未签名 `.app`；`Scripts/validate-app-bundle.py` 验证入口、资源与 bundle 元数据通过。
- 代码卫生：Python 源语法检查、`git diff --check` 通过。

## 本轮发现并修复

`geo_proxy_fixture.py` 通过独立 `swiftc` 编译 GuardCore 时没有包含 SwiftPM 生成的 `Bundle.module` 资源访问器，导致夹具在新增模型生命周期资源后失败。夹具现先构建 GuardCore 并把生成访问器加入编译，loopback TLS/CONNECT、绕过和脱敏断言通过。

安装升级异常恢复会在目录切换前失败时恢复已 bootout 的旧 LaunchAgent 并解除 Agent drain；如果新服务仍加载则保留当前目录和备份，避免对新 Agent 解除旧 drain。`setup_integration_fixture.py` 以确定性的 `launchctl` mock 注入新 Agent bootstrap 失败，确认新服务失败后旧服务恢复、调用顺序正确且旧文件和配置精确还原。夹具不操作真实登录 launchd 域；真实服务注册、bootstrap/bootout 失败和系统恢复仍待桌面发行环境验收。

## 尚未验收

- Developer ID Application 签名、notarization、staple、Gatekeeper：当前机器未配置所需签名身份/profile。
- 菜单栏真实画面、键盘导航与 VoiceOver：当前自动化会话未取得应用辅助功能树，因此不能以打包成功代替验收。
- LaunchAgent 升级回滚已用确定性 `launchctl` 服务模型注入 bootstrap 失败，验证新服务失败后重启旧服务、精确恢复安装文件和配置；真实登录 launchd 域中的 bootout/bootstrap 故障与服务恢复仍未实测。
- CPU/内存和长时间空闲轮询基准、磁盘满与睡眠唤醒故障注入、干净系统升级/卸载演练。
- D01–D04 需要的 DNS Proxy system extension 实际安装与请求绑定路径观测；E08 需要受支持的特权校时状态读取路径。
- 在线信誉供应商的真实响应验收仍缺少用户配置的 ipapi.is API key；不得把供应商夹具通过记录成在线凭据验证。

## 后续发行门禁补充（2026-11-14）

新增本地故障注入 `Tests/Fixtures/agent_storage_failure_fixture.py`：损坏 `sessions.json` 时 Agent 报告 journal 无法读取并保持 hold；损坏 `launch-rate.json` 时 64 项报告中的 G02 保持 unknown。两种场景下通过真实 launcher 请求 `/usr/bin/touch`，退出码为 75 且目标文件未创建。G02 写入失败通过单元测试模拟不可写数据目录，确认内存计数回滚，恢复目录权限后可继续记录。

另复跑 `agent_integration_fixture.py`：在隔离 socket 中 SIGTERM 结束 Agent 后，CLI/launcher 离线启动仍返回 75，目标文件未创建；AgentSupervisor 单元用例另以 SIGKILL 验证自动重启。该离线结果不替代正在执行请求中的网络断开时序测试。

`swift test` 当前 253 项通过。Agent + launcher 空闲资源样本见 [Agent 资源基线](agent-resource-baseline-2026-11-14.md)：当前 Apple silicon/macOS 15.6 下独立 HOME 与 IPC socket 运行 60 秒和 5 分钟，Agent 未退出且可正常 SIGTERM 关闭。它不覆盖多小时、睡眠唤醒、Intel 或繁忙网络。

本地 universal2 build 16 `.app`/DMG 的 bundle、只读挂载和映像校验通过；这仍是未签名构建。Developer ID、公证、Gatekeeper、DNS/校时特权授权，以及目标 UI 的画面、键盘与 VoiceOver 实测仍未通过。Computer Use 连接本轮仍返回 `timeoutReached`，没有获得目标 App AX 树或截图证据。

### 菜单状态表达修正与 build 17

源码复核发现数据不足时菜单栏与主读数使用 `≤上限`，会将安全分上限误读为实际得分；现两处均显示 `—`，上限只用于淡化刻度及说明。菜单品牌图改用 Finder/菜单栏共用的 SafeClaude 路径盾牌模板资源，并保留 SF Symbol fallback。策略摘要现在显示与 assessment context 对应的具体启动/运行门槛；待确认数量固定显示数字，0 项时显示 0；分区标题改为“状态摘要”。更新静态界面 SVG/PNG，覆盖通过、阻断与数据不足三种语义；已查看渲染图。`swift test` 253 项通过，build 17 universal2 `.app` validator、DMG 只读挂载和 `hdiutil verify`、包内 install/upgrade/uninstall fixture 通过。渲染稿不是运行中的 app 截图；桌面窗口、键盘与 VoiceOver 验收仍未取得。

## 后续 UI 可访问性源码复核

设置侧栏项目新增选中状态语义；受管会话刷新按钮播报刷新中/刷新列表，结束按钮播报目标 PID 并提示 Agent 会复核进程身份；门槛加减、报告过滤和规则行的 VoiceOver 名称已接入。`swift test` 183 项、Release build、`.app` 打包和 bundle validator 通过。该检查只证明源码编译及结构有效，尚未通过实际 VoiceOver、键盘焦点顺序或屏幕画面验收。

## D08 客户端证书检查扩展

将 D08 采集扩展到 Claude 用户、项目、托管配置和本次 `--settings`。读取限制为首个 PEM 证书块并只解析有效期；客户端私钥不会被打开，证书路径和内容不会进入 `Findings`/IPC/规则报告。完整扫描无证书时不适用；无效路径、格式或冲突证据保持 critical unknown；已确认的临期/过期证书在证据不完整时同时扣分并 hold。Agent 隔离夹具用一天有效期的合成证书验证内联 `--settings` 启动被阻断，结果与 stderr 不含临时证书/私钥文件名。验证：`swift test` 185 项、Release build、Agent integration fixture、setup fixture、launcher protocol fixture、`.app` bundle validator 和 `git diff --check` 通过。

## 首次启用窗口与本轮联合回归

首次启用集成窗口已接入菜单栏管理，可选择 Claude 可执行文件、终端 PATH shim 和官方 `processWrapper`/失败事件 hook 的安装范围，并在确认前列出即将修改的本机配置。登录启动由随集成登记的用户级 LaunchAgent 管理；移除重复的 `SMAppService.mainApp` 状态开关。README 已同步说明首次启用窗口和随包 universal2 安装器；图形化集成与 App 内 CLI 不依赖系统 Python。

2026-11-14 复验：`swift build -c release`、`swift test`（233 项）、`python3 -m compileall -q Scripts Tests/Fixtures`、未签名发行 `.app` 打包与 `validate-app-bundle.py`、App/LaunchDaemon/DNS extension plist lint、包内安装/升级/卸载夹具、LaunchAgent bootstrap 故障回滚及并发编辑保护夹具均通过。代理、地理代理、exec 透传、Claude runtime 与配置优先级、Agent 全量状态/唤醒复核/真实 Claude 启动拒绝、processWrapper 父会话精确中断和 10 次 preflight latency 夹具通过；本轮 p95 71.0 ms，中位数 35.2 ms。64 项能力矩阵已重新生成，`git diff --check` 通过。

仍未通过正式发行门禁：Developer ID 签名/公证凭据、DNS System Extension 与特权校时实机批准及数据路径、目标 App 实机画面/键盘/VoiceOver 验收、真实睡眠唤醒/网络恢复与磁盘故障、长时资源和干净系统升级卸载演练。临时验证包位于 `/tmp/SafeClaude-continuation-20261114.app`，未安装到用户环境。

## 视觉验收连接状态

本轮尝试通过 Computer Use 连接 `/tmp/SafeClaude-continuation-20261114.app`，macOS UI automation host 返回 `timeoutReached`。没有取得目标 App 窗口、菜单面板或辅助功能树，因此首次启用窗口仍只有源码/编译验收证据；不据此记录视觉、键盘或 VoiceOver 通过。未安装此临时包，也未结束现存 App 进程。

## 卸载级联清理审查

发现现有 setup 卸载事务移除用户级 Agent、shell shim、Claude settings 片段与安装目录，但没有先撤销该安装 bundle 内的 DNS Proxy preference/System Extension 和特权校时 LaunchDaemon。避免在尚未实现级联撤销和失败恢复前暴露会造成残留服务的图形化卸载按钮。待补：App 负责请求停用 DNS preference 并提交扩展 deactivation、撤销 SMAppService daemon，确认系统状态后才调用文件/配置卸载；任一授权/服务操作失败时保留 bundle 与集成，或进入明确可恢复状态。

## 图形化卸载与 Agent 隔离回归

集成管理窗口增加显式危险色卸载按钮和范围确认。卸载首先通过受管 CLI 请求 Agent drain，并要求 Agent 健康且受管会话数为零；之后检查当前 DNS provider 是否为 SafeClaude、自身配置通过复核后才移除 preference，查询系统已安装的 extension 并请求 deactivation，确认完成后注销校时 LaunchDaemon，再调用文件/用户配置卸载事务。`--managed-ui` 避免安装脚本为了删自己的 bundle 而终止当前管理窗口。任一系统服务撤销不确定时保留安装文件并恢复 Agent drain；用户配置冲突时安装目录保留、监测服务状态在窗口说明。

较早记录曾指出卸载后 root 状态快照会残留；该问题后来已在 E08 helper 中通过固定 MachService、串行暂停采样和安全 `unlinkat` 清理路径修复，App 仅在 helper 确认删除后继续注销服务。随后代码审查又发现该特权 XPC 接口未校验客户端身份。本轮已加入 macOS 13+ XPC code-signing requirement：只允许所在 App bundle 的有效签名身份连接，且 helper 与 App 必须有相同 Team ID、App 签名 identifier 必须匹配其 bundle ID；验证失败时 helper 不启动。requirement 语法/输入边界单测通过，但当前无 Developer ID 发行身份，仍未能在真实签名的系统授权环境验证连接允许/拒绝、快照实删及注销失败恢复。

本轮回归 233 项 Swift 测试通过；Release 构建、Python compileall、隔离 setup fixture、最终 `.app` 打包与 bundle validator、发行包内 install/upgrade/uninstall fixture 通过。首次 packaged fixture 暴露 `HOME` 未能隔离 Swift 默认 IPC 路径的问题，现由 setup CLI 调用显式传 `--socket`，fixture 使用临时 socket 后重跑通过。未改动用户 launchd 域；CUA 创建的临时 App/Agent 进程已按精确可执行路径退出，既有审查 App 进程保留。

最终复验包含卸载确认按钮的珊瑚危险操作样式：`swift test` 233 项、Release `.app` 打包、App/LaunchDaemon/DNS extension 4 个 plist lint、bundle validator、包内 install/upgrade/uninstall fixture、隔离 setup 回滚 fixture、Python compileall、64 项能力矩阵生成与 `git diff --check` 均通过。最终临时验收包为 `/tmp/SafeClaude-verified-20261114.app`，未签名且未安装。进程清点保留原有 PID 49474 与 88552；仅退出了本轮 Computer Use 超时尝试创建的临时 App/Agent。
# 2026-11-14 续验：build 18 与发行包生命周期

针对菜单栏在无 Agent 响应时显示采样/离线状态的改动，完成源码回归与最终发行包验证：

- `swift test`：253 项通过。
- 生成 universal2 Release App：`/tmp/SafeClaude-ui-20261114-build18.app`，版本 `0.1.0`，build `18`。
- `validate-app-bundle.py`：通过，覆盖 App 内可执行文件架构、最低系统版本和资源结构。
- 生成 `/tmp/SafeClaude-ui-20261114-build18.dmg`；只读挂载验证 App、Applications 快捷入口与安装说明通过；`hdiutil verify` 校验和有效。
- 对 build 18 运行包内安装/升级/卸载夹具：安装、升级、嵌套 DNS 扩展、设置保留、卸载均通过，且不依赖系统 Python。
- `python3 -m compileall -q Scripts Tests/Fixtures` 与 `git diff --check` 通过。

此证据只覆盖当前 Apple Silicon 主机上的源码、universal2 包结构和隔离生命周期。Developer ID 签名/公证、目标 UI 会话中的实际视觉/键盘/VoiceOver、系统扩展与特权服务批准、Intel/macOS 13 实机、睡眠唤醒/磁盘满和干净系统验收仍是未关闭门禁。

## 计划与实际桌面状态复核

本轮重新核对阶段 01–04 的 Todo 与当前代码/验证产物：阶段 01 的测试工程、64 项矩阵、入口表、代理优先级、延迟记录和供应商评估均已有对应产物；阶段 02/03 的核心启动链、评分、Agent、历史、安装管理、会话处置、菜单设置、通知和脱敏导出均有实现与回归。计划原 SQLite 建议与实际版本化 JSON 历史不一致；当前没有既有数据库需要迁移，因此更新阶段 02 契约为实际格式。历史 JSON 不是整体加密：上下文与出口地址只存 HMAC 摘要，但国家码、采样时间和有限风险标记以 `0600` 文件存放。

尝试启动 build 18 并读取实际桌面画面。`open -n` 成功启动临时包，但屏幕捕获显示 macOS 登录窗口；Computer Use 连接 SafeClaude 超时。因此没有取得菜单栏窗口、键盘焦点或 VoiceOver 树证据，阶段 03 实际 UI 验收仍未通过。按精确可执行文件路径结束了本轮启动的两个临时 App 进程。

对 build 18 `.app` 的静态包扫描未发现 Anthropic API key、常见 GitHub/Slack token、私钥 PEM 标记或 Bearer token 字符串。随后只读检查当前用户 SafeClaude 数据目录的有限文件，确认 `auth-context.json` 和 `history.json` 均为当前 UID 所有、regular file、权限 `0600`；扫描未命中上述凭据模式、IPv4/IPv6 字面量或聊天字段。实际历史 schema 含 `version/entries/context/samples`，样本记录出口地址摘要、国家码、采样时间及可选有限风险值；认证状态只保存白名单模式和时间戳。SafeClaude 专属日志目录不存在。

新增 `SanitizedDiagnosticExport` 作为 App 与测试共用的生产写入器：在同目录创建 `0600` 临时文件，完整写入并 fsync 后以 `renameat` 原子替换目标，再 fsync 目录；只解析父目录符号链接，不跟随目标文件符号链接。落盘测试把虚构凭据、聊天文本、项目路径、代理密码、IPv4 和 IPv6 注入自由文本字段，验证最终 JSON 无这些内容，权限为 `0600`，且原符号链接指向的文件未被覆盖。用户保存面板仍需桌面 UI 会话验收。

设置页“本机网络历史”现明确披露样本最多保留 24 小时、出口地址/上下文只存 HMAC 摘要，以及国家码、ASN、采样时间和风险标记在 `0600` 文件中为明文且未整体加密；可从该页清除。同步更新界面规范。`swift test` 254 项通过；universal2 build 20 App validator、包内 install/upgrade/uninstall、DMG validator 与 checksum 通过。验收包为 `/tmp/SafeClaude-complete-20261114-build20.app` 和 `/tmp/SafeClaude-complete-20261114-build20.dmg`。实际窗口与排版尚未在交互桌面验收。

使用 build 20 完成 README 列出的 14 个集成夹具：代理、地理代理、exec 透传、Claude 合成 API/runtime/wrapper/TLS、Agent 状态与持久化故障、安装升级回滚、发行包内生命周期、合成及真实 Claude wrapper 拒绝处置、预检时延全部通过。首轮发现 `claude_runtime_fixture.py` 对 transient daemon 使用了不适配的 `daemon stop` 调用：session stop 返回成功，但 daemon 未停，临时目录清理与剩余后台写入竞争。夹具现按 Claude 返回的契约使用 `daemon stop --any`，并在删除隔离 HOME 前确认引用该唯一 HOME 的进程已退出；清理若需强制结束隔离进程会使夹具失败。修订后单项与完整回归均通过。测试后检查并清理了 8 个早期遗留的同前缀临时 fixture 目录；无引用这些目录的进程。

新增 `docs/operations/troubleshooting.md` 并链接到 README，覆盖启动 hold、Agent 离线、入口未包装、接入/升级失败、卸载保留与诊断隐私。内容按当前 CLI JSON/退出码、App 操作和安装器恢复语义编写；这是一份本地试用手册，不作为正式发行说明。

## ProxyCheck B07 源记录时效复核

ProxyCheck 响应的 `last_updated` 是供应商记录更新时间，不能用本地请求时间代替。B07 的住宅代理运营方和地址设备估算信号现要求严格解析 ISO 8601 时间戳，且年龄在 -5 秒至 15 分钟内；缺失、畸形或更旧的记录保留 unknown。地址设备数阈值仍为 SafeClaude 启发式 25，风险状态仍保留 P2P unknown/hold。ProxyCheck 结果缓存也收紧到 15 分钟，采用供应商对匿名 IP 结果建议的最长缓存间隔作为全体结果的保守上限。

本轮修改后的 `swift test` 首轮 256 项通过；之后补入时间戳格式回归，需再跑完整套件。发行 `.app`/DMG、包内安装生命周期夹具与能力矩阵尚待本轮最终复验。当前环境访问官方 OpenAPI URL 返回 HTTP 403；未用真实用户 IP 请求供应商。

B07 时效修正后的复验已完成：`swift test` 257 项通过；64 项能力矩阵重新生成；Python compileall 与 `git diff --check` 通过。universal2 Release build 22 `/tmp/SafeClaude-b07-20261114-build22.app` 通过 bundle validator；DMG `/tmp/SafeClaude-b07-20261114-build22.dmg` 通过结构检查和 `hdiutil verify`；发行包 install/upgrade/uninstall fixture 确认嵌套 DNS 扩展、保留用户设置且不依赖系统 Python。该包未签名，不能视为可交付公证发行包。

## 设置界面视觉一致性续验

按用户对默认原生界面观感的反馈，将菜单和设置 UI 的色板统一为冷调石墨与柔和青柠色，并让设置侧栏复用正式盾牌品牌标记。页头移除装饰性章节数字，使用对应符号、中文标题和说明形成清楚层级。保留已有导航、文案信息和操作流程。全量 `swift test` 257 项通过；universal2 Release build 23 `/tmp/SafeClaude-ui-refresh-20261114-build23.app` 通过 App validator，DMG `/tmp/SafeClaude-ui-refresh-20261114-build23.dmg` 通过结构校验与 `hdiutil verify`；包内安装/升级/卸载 fixture 通过，设置保留且不需要系统 Python。

Computer Use host 在取得目标 App 状态时返回 `timeoutReached`。因此本轮尚无运行界面截图、键盘焦点或 VoiceOver 树证据；UI 实机门禁继续未通过，须在桌面 host 可用时复验。当前产物未签名。

本次色板的关键文字组合经 WCAG 相对亮度计算：主文字/画布 16.46:1、辅助文字/画布 8.96:1、主按钮文字/填充 11.76:1；安全、提醒、风险状态色与画布分别为 12.90:1、10.62:1、7.06:1，均高于正文 AA 对比度要求。计算值证明所测颜色组合的对比度，不替代实际运行画面的字号、布局与辅助功能检查。

## E09 虚拟化信号接入与发行包回归

macOS 快照现读取 `kern.hv_vmm_present`，并严格校验 sysctl 返回结果。内核报告 VMM 来宾时 E09 扣 3 分；读取失败或响应格式异常时 E09 保持非 critical unknown，报告来源通过 IPC 白名单显示为“虚拟化环境检测不可用”。Apple Open Source 的 XNU 实现表明 arm64 使用设备树 `vmm-present`，x86_64 使用 CPUID VMM 位；研究记录固定到源码 revision `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`。该指标仅表示内核报告的来宾状态。

全量 `swift test` 260 项通过；Agent 综合夹具通过并从真实本机 Agent 状态观察到 E09=`passed`；64 项能力矩阵重生成，Python compileall 通过。universal2 build 24 `/tmp/SafeClaude-e09-20261114-build24.app` 通过 bundle validator；DMG `/tmp/SafeClaude-e09-20261114-build24.dmg` 通过 validator 与 `hdiutil verify`；发行包 install/upgrade/uninstall fixture 通过。包仍未签名。

## E09 SSH 远程 shell 信号与 build 25

Claude 启动上下文现在将 `SSH_CONNECTION`、`SSH_CLIENT`、`SSH_TTY` 交给本机 Agent。采集器校验字段结构，仅保留 `hasRemoteShellContext` 布尔值；不保留地址、端口或 TTY 路径。有效 SSH 标记与内核 VMM 来宾信号分别按 E09 计分。检测目录、研究记录和生成的 64 项能力矩阵已同步说明该项是低权重启发式。

验证结果：

- `swift test`：261 项通过。
- `agent_integration_fixture.py`：通过；隔离 Claude 启动环境带合成 SSH 标记时，Agent 报告 E09=`triggered`，扣 3 分。
- 本地集成夹具通过，包含代理、地理代理、exec 透传、Claude runtime/proxy/TLS、Agent 状态与持久化故障、setup 回滚、真实 Claude wrapper 父会话处置和预检时延；发行包 install/upgrade/uninstall 夹具另行通过。预检 10 次均低于 2.5 秒，p95 72.6 ms，中位数 34.7 ms。旧的 `claude_wrapper_rejection_fixture.py` 仍只报告超时，不能用作处置成功证据；验证以 `wrapper_agent_rejection_fixture.py --real-claude` 的 Agent 联合夹具为准，该夹具确认受管父进程收到中断且无关进程存活。
- `python3 -m compileall -q Scripts Tests/Fixtures`、64 项能力矩阵生成及 `git diff --check` 通过。
- universal2 Release build 25：`/tmp/SafeClaude-e09-20261114-build25.app`；App validator 通过。
- DMG：`/tmp/SafeClaude-e09-20261114-build25.dmg`；DMG validator、`hdiutil verify` 和包内安装/升级/卸载夹具通过。包内安装器不依赖系统 Python，升级保留设置并携带嵌套 DNS extension。

当前钥匙串仅有 Apple Development 身份；没有 Developer ID Application 身份。正式签名、公证、staple 与 Gatekeeper 验收因此不能在本机完成。桌面自动化 host 仍未提供 SafeClaude 的窗口/辅助功能树；菜单栏实画面、键盘焦点和 VoiceOver 未验收。真实 DNS System Extension/特权校时服务批准与流量路径、Intel/macOS 13 实机、磁盘满及长时睡眠恢复也仍未关闭。build 25 是未签名本地验收包，不是可公开发行版本。

## 设置控制台续修与 build 26

设置窗口改用更宽的工作区和清晰的分区标题层级；侧栏明确标注本机安全控制台及数据留在设备上的边界。STUN 地址、Claude executable、ipapi.is 与 ProxyCheck key 输入统一使用深色产品输入表面，并在键盘聚焦时显示青柠描边。设置功能、字段、导航名称和操作顺序均保留。窗口默认 1000×760pt，最小 900×660pt。

`swift test` 261 项通过；Release universal2 build 26 `/tmp/SafeClaude-ui-20261114-build26.app` 通过 App validator 与包内 install/upgrade/uninstall fixture；DMG `/tmp/SafeClaude-ui-20261114-build26.dmg` 通过 DMG validator、`hdiutil verify`；plist/entitlements lint、Python compileall 和 `git diff --check` 通过。系统截图仍为黑色登录屏，Computer Use host 返回 timeout，因此这次只有源码与构建验收，没有运行画面、键盘路径和 VoiceOver 结果。包未签名。

## F01 代理变量冲突覆盖与 build 27

本机 F01 现逐对比较 `http_proxy/HTTP_PROXY`、`https_proxy/HTTPS_PROXY`、`all_proxy/ALL_PROXY`、`no_proxy/NO_PROXY`。只有两种大小写值不同才计分；报告仅含键名。四组冲突的单元测试确认 F01 扣 8 分，等值代理不会误触发。Agent + launcher 夹具用含合成用户名、口令、地址和端口的冲突 `ALL_PROXY` 调用 `/usr/bin/touch`，确认启动以 75 拒绝、目标文件未创建、F01 为 triggered 且输出不含代理字段和值。

`swift test` 264 项通过；能力矩阵重生成；Agent 集成夹具、Python compileall 和 `git diff --check` 通过。universal2 build 27 `/tmp/SafeClaude-f01-20261114-build27.app` 通过 App validator、发行包安装/升级/卸载夹具；DMG `/tmp/SafeClaude-f01-20261114-build27.dmg` 通过 DMG validator 与 `hdiutil verify`。本包未签名。


## 当前源码全量回归与真实 Claude 联合验收（build 35）

2026-11-14 对当前工作区重跑 `swift test`：277 项通过、0 失败。以下隔离夹具通过：`claude_runtime_fixture.py`、`claude_proxy_runtime_fixture.py`、`claude_tls_runtime_fixture.py`、`launcher_protocol_fixture.py`、`launchd_agent_fixture.py`、`unmanaged_process_fixture.py`，以及 `wrapper_agent_rejection_fixture.py --real-claude`。真实 Claude 版本的官方 `processWrapper` 子进程拒绝路径确认受管父会话收到中断、无关进程保持运行；fixture 不发模型请求。`preflight_latency_fixture.py` 完成 10 次实际本机 Agent + launcher + Claude `--version` 预检，均低于 2.5 秒，中位数 34.8 ms，p95/最大值 67.3 ms。

build 35 `/tmp/SafeClaude-design-20261114-build35.app` 由当前 UI 源码生成，bundle validator 与包内 install/upgrade/uninstall fixture 通过；对应 DMG `/tmp/SafeClaude-design-20261114-build35.dmg` 通过结构验证及 `hdiutil verify`，SHA-256 为 `1085730cc36bee80b6929cf8e3a31ce5726bae565205c62664f3916dd2c6c8f0`。F04 Debug Agent 代次变化夹具通过，其他代理、setup、持久化失败与 launcher 集成夹具结果见长期进度记录。

本次桌面宿主复查仍未列出 SafeClaude App，且浏览器自动化宿主报告不可用；因此运行中窗口截图、浅/深外观、键盘与 VoiceOver 仍无实测证据。build 35 未签名，不代表正式发行；Developer ID/公证、System Extension/特权服务实际批准、Intel/macOS 13、真实睡眠与磁盘故障、长时运行和干净系统演练仍未关闭。


## build 36 源码清理复验

删除已无调用方的 `SettingsSection.kicker` 英文标题字段，保持页面已采用的中文图标标题与说明。清理后的当前 SwiftUI 源码再次通过 `swift test`（277 项、0 失败）。universal2 build 36 `/tmp/SafeClaude-design-20261114-build36.app` 已通过 bundle validator 与包内 install/upgrade/uninstall fixture；其 App、Agent、CLI 均含 arm64/x86_64。当前 Apple silicon 主机以 Rosetta 实际启动 x86_64 Agent 并建立隔离 IPC socket，SIGTERM 后按预期以 signal 15 退出；该结果不替代 Intel 实机验收。对应 DMG `/tmp/SafeClaude-design-20261114-build36.dmg` 通过只读 validator 和 `hdiutil verify`，SHA-256 为 `af75c4685ca8e2f87dde945a6835946d0310f31341f918a81b096999b7d41981`。15 分钟隔离 Agent 基准已完成（900 秒、446 个区间样本）：CPU 均值/p95=0.146%/0.498%，RSS 均值/峰值=15.66/16.14 MiB；详见资源基线报告。


## F04 与真实 Claude Code 联合运行夹具

扩展 `managed_generation_fixture.py --real-claude`，串接本机 Claude Code、官方 `processWrapper` 启动路径、真实 Agent managed-session monitor 和运行策略代次变化。合成 API 环境与隔离配置下，Claude 后台子进程停在测试门闸，不会发送模型请求；夹具登记实际 Claude 进程身份、确认基线 F04 通过、把 `runtimeMinimumScore` 从 80 改为 81，Agent 随后触发 F04 并只中断该受管 Claude 会话，旁观进程继续运行。默认合成父进程模式及真实 Claude 模式本轮均通过，结束后未留下 fixture/wrapper 进程。README 已加入命令和运行边界说明。


## 当前钥匙串发行预检

2026-11-14 重查 `security find-identity -v -p codesigning`：仅有 1 个 Apple Development 身份，无 Developer ID Application。用 release 脚本执行 build 36 参数预检，在创建输出目录或构建发行物之前按设计失败，stderr 为 `matching Developer ID Application signing identity is unavailable`。因此正式签名、公证与 Gatekeeper 检查的阻断来自发行身份缺失；本地未签名 DMG 校验已经完成。


## 15 分钟隔离 Agent 空闲资源复测

使用 build 35 包内 Agent，在临时 HOME 与独立 IPC socket 中连续运行 900 秒，每 2 秒采集一次 CPU 时间差和 RSS；Agent 全程存活并在结束时正常响应 SIGTERM，共取得 446 个区间样本。CPU 均值 0.146%、p95 0.498%；RSS 均值 15.66 MiB、峰值 16.14 MiB。无 Claude 会话、无模型请求。详见 [资源基线报告](agent-resource-baseline-2026-11-14.md)。这是单机空闲样本，不代表睡眠唤醒、活动网络、长于 15 分钟或 Intel 实机结果。


build 36 实机 UI 宿主复试使用明确 `.app` 路径，仍返回 `timeoutReached`；精确退出本轮启动的临时 App 进程。未获取窗口截图或 AX 树，界面实机门禁仍未通过。


## x86_64 Agent/CLI IPC 复跑夹具

新增 `Tests/Fixtures/rosetta_integration_fixture.py`：先校验包内 Agent 与 CLI 都有 x86_64 slice，再用 x86_64 切片启动 Agent 和 CLI，在隔离 HOME/socket 中经 IPC 取得完整 64 项规则状态，最后按 SIGTERM 清理 Agent。本机 Apple silicon + Rosetta 对 build 36 实跑通过，决策为 hold（缺少实时环境证据时符合 fail-closed 行为）。README 和阶段 01 兼容记录已加入命令。该夹具验证通用二进制执行与 IPC 协议，不替代 Intel 主机、macOS 13、system extension 或 LaunchDaemon 的实机验收。


## 真实 Claude 运行中的网络代次变化夹具

Debug Agent 新增 `fixture-advance-network-epoch` 测试动作，仅能推进进程内网络代次，不修改系统网络配置，也不会包含在 Release 构建中。`managed_generation_fixture.py --real-claude --network-change` 以 81 分运行阈值启动真实 Claude 官方 wrapper 会话；确认 F04 基线通过后，通过测试 IPC 推进代次，Agent 将其评为 F04 风险并中断受管 Claude 父会话，旁观进程保持运行。Claude 子进程仍停在隔离门闸，没有发起模型请求。真实 Claude 网络代次和运行策略代次两种模式本轮均通过。该结果验证 Agent 网络代次处置链路，不等同于真实 macOS 路由变化采集验收。


## build 37 与 F04 网络代次夹具最终回归

加入仅 `#if DEBUG` 编译的 `fixture-advance-network-epoch` IPC 动作；Release Agent 二进制字符串检查确认不包含此动作。全量 `swift test` 277 项、0 失败。真实 Claude Code + 官方 wrapper 的 F04 运行策略变化与 Debug 网络代次变化两种夹具复跑均通过；受管 Claude 被中断、旁观进程存活，均未发送模型请求。build 37 `/tmp/SafeClaude-design-20261114-build37.app` 通过 bundle validator 与包内 install/upgrade/uninstall fixture。对应 DMG `/tmp/SafeClaude-design-20261114-build37.dmg` 通过 DMG validator 和 `hdiutil verify`，SHA-256=`cebd13395a379449b6d8b88d184f2436912172941afc6c7ac67f67a6f1abcce6`。DMG 首次构建遇到一次 `hdiutil` 资源忙，确认无 SafeClaude 挂载或遗留进程后重试成功。build 37 Rosetta x86_64 Agent/CLI IPC 夹具再次通过；F04 Debug 动作加入后，完整 `agent_integration_fixture.py` 复跑也通过。


## 真实 ENOSPC 磁盘压力夹具

新增 `Tests/Fixtures/disk_pressure_fixture.py`：在 `/tmp` 临时目录创建 64 MiB sparse HFS+ 磁盘映像、挂载后填充到实际 `ENOSPC`，让当前 Debug Agent 的 `launch-rate.json` 与 `sessions.json` 位于该卷。两种写入都返回固定 fail-closed 阻断状态，Agent 本身持续运行。夹具 finally 中先关闭 Agent，再卸载映像；执行结束确认临时卷和临时进程均已清理，用户卷未改动。README 已加入该夹具和范围说明。该证据覆盖真实 ENOSPC 持久化写失败，不替代真实睡眠唤醒/路由恢复验收。

基于含该夹具的当前源码完成 build 38 回归：全量 `swift test` 277 项、0 失败；真实临时 HFS+ 卷 ENOSPC 夹具再次通过，启动频率和会话 journal 写入均 hold，Agent 存活且用户卷未改动。`/tmp/SafeClaude-design-20261114-build38.app` 通过 universal2 bundle validator、包内安装/升级/卸载 fixture、Rosetta x86_64 Agent/CLI IPC fixture（完整 64 项状态）；Release Agent 不含网络代次、启动频率和会话记录三种 Debug fixture IPC 字符串。对应 `/tmp/SafeClaude-design-20261114-build38.dmg` 通过只读 validator 与 `hdiutil verify`，SHA-256=`823ae83a967db48d09d5b96b8647477455138396f8acaaeedc902f21d26473d8`。Python compileall 与 `git diff --check` 通过。该回归不关闭真实睡眠唤醒、桌面 UI/键盘/VoiceOver、系统扩展/特权授权、Intel/macOS 13、签名公证和干净系统门禁。

build 38 的桌面 UI 连接重试：Computer Use 对 App bundle 返回 `timeoutReached`，未取得运行窗口、截图、焦点或 AX/VoiceOver 树，因此 UI 门禁保持未验收。2026-11-14 本机为 arm64 macOS 15.6；钥匙串只有 Apple Development identity，没有 Developer ID Application，正式签名/公证/Gatekeeper 验证需要发行身份和 notary profile。


## 主分数面板视觉修订与 build 39

按用户对旧版界面观感的反馈重新审查 SwiftUI 层级。菜单栏主分数面板改为深石墨绿仪表面，在浅色系统外观中形成焦点，在深色模式中继续融入画布；通过青柠、待确认琥珀、阻断珊瑚及白色数字保证状态有明确区分，不用发光或半透明装饰。色值对比计算结果：主文字 14.96:1、辅助文字 7.85:1、通过色 11.96:1、待确认色 10.09:1、阻断色 7.20:1；增强对比纯黑底下分别为 19.39:1、10.17:1、15.49:1、13.07:1、9.33:1。20 段仍只表达分数，不与检查完成度混淆。

全量 `swift test` 277 项、0 失败。universal2 build 39 `/tmp/SafeClaude-design-20261114-build39.app` 通过 App bundle validator、随包 install/upgrade/uninstall fixture 及 Rosetta x86_64 Agent/CLI IPC fixture（64 项状态）。DMG `/tmp/SafeClaude-design-20261114-build39.dmg` 通过 validator 和 `hdiutil verify`；SHA-256=`9ffedffd7d664dae4b49293eff907462faf57a93d1c8ec3cb0661be909405ca2`。Computer Use 查询仍超时，系统截屏是黑色登录界面，没有运行窗口/键盘/AX/VoiceOver 证据，所以真实 UI 门禁继续保持未验收。

后续将同一视觉方向推广到设置控制台：防护、网络和诊断页使用开放式分组及分隔线，受管会话使用进程列表行，减少重复的整页圆角卡片层级。最新全量 `swift test` 277 项通过。build 40 `/tmp/SafeClaude-design-20261114-build40.app` 通过 universal2 App validator、包内 install/upgrade/uninstall fixture、Rosetta x86_64 Agent/CLI IPC fixture（64 项状态）；Release Agent 不含三个 Debug fixture IPC 字符串。`/tmp/SafeClaude-design-20261114-build40.dmg` 通过 DMG validator 和 `hdiutil verify`，SHA-256=`9fad8009fbe018ccb0d34606438381396753c9b245914344f5286e7652f23960`。Python compileall 与 `git diff --check` 通过。UI host 仍不可用，截屏仍为登录界面，桌面视觉、键盘和 VoiceOver 验收未关闭。


## 当前用户 launchd 与 40 次启动预检复验

在当前用户的 `gui/501` launchd 域运行 `launchd_agent_fixture.py`：唯一临时服务由 launchd 启动，向该服务发送 SIGKILL 后确认 PID 改变且 Agent IPC 恢复；夹具退出后 `/bin/launchctl list` 未发现 fixture service。检查夹具时发现原 plist 没有设置临时 `HOME`，已修复为私有临时目录、受限 PATH 和独立 socket；清理现在在 bootstrap 尝试后始终按唯一 service target 执行 bootout。修订后的夹具再次通过。该实验证明当前登录用户 launchd 的启动/崩溃恢复行为，不覆盖真实安装器的 launchd 注册和干净系统升级回滚。

将 `preflight_latency_fixture.py` 加入 `--samples` 参数（范围 10–1000，默认 10），并以当前 Agent/launcher/真实 Claude `--version` 完成最终 40 次样本。40/40 次返回预期退出码 75，确认 D05 合成 TLS 风险阻断；中位数 34.1ms、p95 34.6ms、最大/首样本 68.3ms，全部低于 2.5 秒。测试不携带登录凭据，不发起模型请求。该分布基于已运行的隔离 Agent，不替代独立冷启动、活动网络、多小时及睡眠唤醒测量。夹具和文档通过 Python 编译与 `git diff --check`。


## 首次接入/规则报告界面续修与 build 41

首次接入窗口改为三个有顺序的步骤，以编号、开放分组和细分隔线展示 Claude 可执行文件选择、保护入口与启用前检查；运行/错误状态使用带色标的内联说明。64 项规则报告移除英文大写眉题及胶囊筛选，分类改用文字与底部选中标记，只有展开的规则行显示强调背景。全量 `swift test` 277 项、0 失败。universal2 build 41 `/tmp/SafeClaude-design-20261114-build41.app` 通过 bundle validator、发行包 install/upgrade/uninstall fixture 与 Rosetta x86_64 Agent/CLI IPC（64 项状态）；DMG `/tmp/SafeClaude-design-20261114-build41.dmg` 通过只读 validator 和 `hdiutil verify`，SHA-256=`9867b0494fc0e625e27c7783d531b3428e74bf953caab69da0d0b4e8b10f45e2`。Python compileall 与 `git diff --check` 通过。当前桌面仍未提供 SafeClaude 运行窗口，键盘及 VoiceOver 还没有实机证据。
