# 阶段 01：可行性与兼容基线

## 阶段目标

用本地可观察实验确认入口覆盖、网络路径等价性和 launcher 时间预算，并将 64 项目录转成逐条可执行的采集能力矩阵。

## 进入条件

用户明确开始实施；已读产品设计、评分契约、研究报告和 `progress.md`。

## 范围

检测/launcher 实验、兼容矩阵、测试夹具、供应商评估；不先做完整客户端。

## 非目标

真实制造违规访问、提交模型请求、读取账户 token、购买账号/代理、直接启用系统扩展。

## 当前证据

实现和验证产物见 `docs/validation/phase-01/`：包括 64 项采集矩阵、入口兼容表、代理优先级与范围、可观察代理/exec 夹具、供应商结论及预检时延。矩阵中保留未支持和 critical unknown 项；夹具结论只覆盖记录的 Claude、macOS 与启动入口，不外推到未测宿主。

### DNS 路径证据边界（2026-11-14）

macOS `Network.framework` connection establishment report 能列出该 `NWConnection` 建连过程中执行的解析步骤、DNS 响应来源、解析传输协议和成功 endpoint。它只描述生成该报告的 Network.framework 连接；SafeClaude 当前通过 curl 进行 HTTPS trace，不能把另建的 `NWConnection` 报告嫁接为 curl 或 Claude Code 请求的 DNS 证据。

Apple 的 `NEDNSProxyProvider` 是系统 DNS 流量代理扩展，接收应用发往 UDP/TCP 53 端口的 DNS flow；实现需要 DNS Proxy Network Extension capability。DoH/DoT 不会自动经过传统 53 端口代理，必须分别按实际生效的加密 resolver 配置和流量 endpoint 绑定证据。

### 当前实现状态（2026-11-14）

早期研究所述的“需要独立 extension target”已在后续实现中完成：产品现在包含独立 `SafeClaudeDNS` System Extension target、App Group 短期证据 spool、App 内显式启停与冲突说明，以及 Agent 侧逐项规则判断。扩展部署目标为 macOS 15；macOS 13/14 不支持此采集路径，D01–D04 因而保持 critical unknown/hold。

扩展依据 DNS flow 的 audit token 与进程启动代次识别来源，再让 Agent 与 SessionJournal 中登记的会话身份复核。53 端口查询按 UDP/TCP 原 resolver 转发；标准 853 DoT 使用 TLS/TCP；DoH 只在系统配置能唯一提供 HTTPS URL、server IP/TLS 身份且与该 flow 完全匹配时探测。D01 比较实际 resolver digest 与 SystemConfiguration 当前活动 resolver；D02/D03 在用户启用 IPWho 地理查询后，将 resolver 出口 IP 短暂保留在内存并换成仅含国家码与 resolver digest 的采样记录；D04 观察适用于 Claude 目标域名的 DoH/DoT 设置及会话内加密降级。缺少扩展批准、来源身份、配置匹配、必要 resolver 样本或新鲜度时仍按 critical unknown/hold；配置快照本身不会作为真实 flow 证据。

本机可完成的 parser、评分、脱敏、状态协议和包结构回归已经覆盖上述路径。当前仍未通过的部分是 Developer ID/公证签名、macOS 系统设置批准后的真实 DNS flow、真实 DoT/DoH resolver 端到端证书与响应、DNS Proxy 与既有系统扩展冲突下的真实恢复，以及 macOS 13/14 的平台边界实测。启用 DNS Proxy 会影响其他 DNS Proxy 配置，因此必须由用户明确启用；停用与卸载恢复仍需发行环境验收。

### G07 Claude 项目记忆目录覆盖（2026-11-14）

Claude Code 的设置参考将 `autoMemoryDirectory` 定义为可在任一 settings 文件指定的自定义目录；会话文档说明 `CLAUDE_CODE_PROJECT_DIR_NAME` 仅在与 `CLAUDE_CONFIG_DIR` 同时设置时生效，并覆盖默认的 `projects/<derived-name>`。采集器仅将后者作为实际进程环境中的目录名覆盖读取，不从 settings 的 `env` 块推断它；名称必须是单一安全路径组件。唯一用户/托管设置和显式 `--settings` 自定义目录会在本机做无正文 metadata census，配置路径不会进入 Codable `Findings`、IPC 或规则报告。项目来源、范围冲突/重复、无效路径、worktree 映射和默认长路径哈希仍保持 unknown；不使用来源优先级不明的项目设置使 G07 错误通过。

来源：[Claude Code settings reference](https://code.claude.com/docs/en/settings-reference#automemorydirectory)、[environment variables](https://code.claude.com/docs/en/env-vars#claude-code-project-dir-name)、[memory](https://code.claude.com/docs/en/memory#storage-location)，通过 HTTP 获取于 2026-11-14。

### Network Extension SDK 接口复核（2026-11-14）

本机 Xcode 26.0.1 / macOS SDK 26 headers 确认：

- `NEDNSProxyProvider.handleNewFlow(_:)` 是 macOS 10.15 起可用的 provider 入口；UDP 专用的新 endpoint API 仅 macOS 15 起可用，旧 `NWEndpoint` UDP API 在 macOS 15 被标为 deprecated。产品仍支持 macOS 13，因此实现需要按系统版本兼容调用，不能只采用 macOS 15 API。
- flow 的 `metaData.sourceAppAuditToken` 在 macOS 10.15 起可用，`sourceAppSigningIdentifier` 与 `sourceAppUniqueIdentifier` 同时提供。系统进程来源可为空；对缺失 token 或 PID 无法复核 executable identity 的 flow 必须保持 unknown，不能仅凭签名 identifier 将它关联到某个受管会话。
- SDK 的公开 `bsm/libbsm.h` 暴露 `audit_token_to_pid` 和 `audit_token_to_pidversion`；PID 仍可能复用，后续归属校验需把 audit token 中的 PID version 与 PID、可执行文件身份及受管会话启动身份一并核对。
- `NEDNSProxyManager.enabled` 的文档明确指出启用本产品 DNS Proxy 会禁用其他 App 的 DNS proxy 配置；保存自身 DNS Proxy preference 也会使其启用。因此这不是静默后台采集：需要清晰的显式开启流程、现有配置冲突处理、状态监测及可验证的停用/卸载恢复。扩展未签名、未批准、失效或无法取得来源身份时，D01–D04 继续 critical unknown 并阻断。

上述 SDK header 复核只确认接口存在和版本边界；extension target、flow 转发、来源核验与证据通道现已在源码和本地构建夹具中实现，但这不代表已完成签名、公证、真实用户批准或系统级 DNS flow 实测。

### Claude Code 失败事件元数据（2026-11-14）

读取 Claude Code 官方 hooks 文档确认，`StopFailure` 在一次 turn 因 API 错误结束时触发，payload 提供固定 `error` 类别及 `session_id`；同时还可能包含 `error_details` 和 `last_assistant_message`。实现仅白名单接受错误类别，并将 `session_id` 转成 SHA-256 摘要；不把错误详情或消息字段纳入模型。认证/账号类类别映射到 G04，其余 API 失败类别映射到 G03。

该事件表示 API 错误结束的 turn，不等于底层每一次自动 retry；G03 的“错误/重试”计数只能以事件数作为保守代理，不能将其标注为精确 retry 数。官方说明 `StopFailure` hook 没有决策控制能力，因此该采集只能触发 Agent 后续重评估，不能拦截已经发生的请求。`cloud_credential_error` 的专用分类要求 Claude Code 2.1.267 或更新版本；其他错误类型仍以官方枚举为准。

SafeClaude 安装器已将 hook 合并到用户已有 `settings.hooks`，精确保存插入片段以便卸载只移除自身配置；事件经本机 Agent IPC 关联到已登记 Claude 祖先进程。Agent 仅将类别、散列后的 session_id 与时间写入权限为 0600 的有界文件。10 次以上 API 错误 turn/分钟触发 G03；3 次认证风险类别/10 分钟触发 G04。触发后 Agent 先返回 hook 响应，再异步对核验身份的受管 Claude 祖先进程发退出信号，避免 hook 等待与结束父进程形成死锁。未安装 hook、Agent 不可用或事件文件故障时不会将规则报告为通过。

`cloud_credential_error` 的专用分类要求 Claude Code 2.1.267+；较早版本的凭据加载错误可能表现为 `server_error` 或 `unknown`，这两类按认证风险保守计入 G04。`StopFailure` 无法控制已结束的 API turn；超过阈值后的处置只能影响后续会话活动。本机 Claude Code 2.1.323 已通过隔离 HOME 的 HTTP/HTTPS CONNECT、NO_PROXY、用户/项目/local settings 路由优先级与官方 `processWrapper` 测试；安装升级 hook 合并和回滚由隔离安装夹具验证。真实 Claude 父会话与 wrapper 错误阈值处置也通过，但 StopFailure 错误事件由夹具注入，尚未验证真实用户配置中 hooks 被禁用/覆盖时的接入行为，或 Claude 自身发出的真实错误事件 payload。

来源：Anthropic Claude Code 官方 [Hooks reference](https://code.claude.com/docs/en/hooks)，读取于 2026-11-14。

### E08 自动网络校时读取（2026-11-14）

本机 macOS 15.6 用户态执行 `/usr/sbin/systemsetup -getusingnetworktime` 明确要求管理员权限；`timed` 守护进程存在、自动时区 plist 或 HTTPS Date 采样都不能证明系统网络校时开关已开启。

实现为 App 内的 `SMAppService.daemon` LaunchDaemon。用户从网络设置主动注册并批准后，随包 helper 每分钟只运行固定的 `systemsetup -getusingnetworktime`，环境限定 `PATH` 和 `LC_ALL`，严格解析 `Network Time: On/Off`。持久状态只含版本、枚举值和采样时间；root 所有目录下以 root:wheel、0644、临时文件加 rename 原子更新。Agent 通过 `O_NOFOLLOW` 读取，核对 root owner、文件类型、权限、4KB 上限和 180 秒 TTL。开启记为通过，关闭扣 E08 权重；权限不足、其他输出、文件缺失/过期/损坏均为 critical unknown。采样失败会写入 `unavailable`，不会沿用旧的 On 状态。

目前已有 parser/评分测试、未签名包的 helper 与 LaunchDaemon 结构校验及隔离安装/升级夹具。当前环境无 Developer ID Application 身份，尚未实测 macOS 后台服务授权、root 下 `systemsetup` 的实际输出、系统设置批准与撤销、root-owned 状态文件的真实读写和正式卸载清理；这些发行门禁通过前，E08 仍会按 unknown/hold 处理。

参考：

- [Apple SMAppService daemon](https://developer.apple.com/documentation/servicemanagement/smappservice/daemon(plistname:))
- [Apple Network connection establishment report](https://developer.apple.com/documentation/network/nw_establishment_report_t)
- [Apple NEDNSProxyProvider](https://developer.apple.com/documentation/networkextension/nednsproxyprovider)
- [Apple Network Extensions entitlement](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.networking.networkextension)
- [Apple DNS proxy provider deployment](https://developer.apple.com/documentation/networkextension/dns-proxy-provider)

## 设计与实施方案

建立可观测 HTTP CONNECT 测试代理和本地模拟目标，记录目的域名、地址族、是否经过预期路径，不记录认证内容。用官方命令最小无推理路径及模拟可执行验证参数/exec；需真实登录的测试单独标明前提，不用缺少账号作为“已经覆盖”。

矩阵至少包含：当前可获得的兼容版本、最低 wrapper 版本、旧版；原生/Homebrew/npm 来源；zsh/bash、IDE 自定义入口、绝对路径、嵌套 self-spawn、已有 supervisor、Remote Control/teams、深链接缺口；额外自动化和插件宿主入口作为探测项目，不预先声称兼容。无法获得的旧版本记录未验证。

网络矩阵至少包含：直连、HTTP CONNECT、含凭据代理、NO_PROXY、大小写变量冲突、项目/用户/托管配置、IPv4/IPv6、按域名分流、代理故障、企业 CA。native 库不能等价的场景明确降级。

逐条盘点 A01–H04：采集输入、获取方式、实际 API/配置字段、适用前提、隐私过滤、缓存 TTL、事件触发、成功/失败夹具。额外验证系统/进程时区与 locale、地区语言映射、DST、多时区国家、模型/记忆/诊断计数元数据。可以采集就进入激活规则，不因来源是社区经验而过滤。

## Todo

- [x] 建立最小测试工程和可观察代理/echo 夹具（见 `Tests/Fixtures/`）。
- [x] 输出 64 项逐条采集矩阵，区分已支持、当前不适用、暂时失败和没有稳定来源（见 `docs/validation/phase-01/capability-matrix.md`）。
- [x] 输出逐入口、逐版本的实际覆盖表与发现方式（见 `docs/validation/phase-01/compatibility.md`；未测试入口明确标注）。
- [x] 输出有效代理配置解析优先级和 provider 范围（见兼容报告与网络验证记录）。
- [x] 对冷/热路径计时，验证 2.5 秒预算下超时行为（见阶段 01 观察记录和阶段 04 延迟复验；不代表所有硬件）。
- [x] 明确可用的商用 IP 信誉供应商与不使用的内部接口（见 `docs/validation/phase-01/review-01.md`）。
- [x] 调整设计中被实测否定的假设并记录偏差（包括 DNS 观测边界、DoT/DoH 传输和 `StopFailure` 语义）。

## 测试方案

配置解析单元测试；代理/地址族集成测试；不同入口观察到 launcher 是否执行；真实 exec 的 TTY/stdin/stdout/退出状态验证。保存机型、OS、Claude 版本、命令和脱敏输出。

## 输出契约

仓库内 `docs/validation/phase-01/` 保存兼容报告、64 项能力矩阵、实验方法、性能原始记录；测试夹具可本地复跑，不依赖真实 Claude 凭据。

## 完成门禁

每个首版支持入口有成功/拒绝/超时证据；不同 shell 配置确实形成不同 context；64 项均有采集结论与真实原因，不能凭证据级别删项；时区/语言一致性有夹具；无认证内容进入日志。无法取得的数据必须有对应 hold/unsupported 语义。

## 交付物

兼容矩阵、实验夹具、性能基线、供应商结论、更新后的设计和长期进度。
