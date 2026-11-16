# 阶段 04：生产验证与发行

## 阶段目标

形成可安装、升级、卸载和诊断的签名发行包，并用明确证据限定性能、覆盖与故障行为。

## 进入条件

阶段 03 的核心运行时代码与 UI 已实现；阶段门禁尚未通过，菜单栏实际画面、键盘操作、VoiceOver 和减少透明度仍缺桌面会话验收。本阶段只能记录可独立完成的发行验证，不能据此宣布生产发行完成。

## 范围

故障注入、隐私与供应链检查、打包签名、公证、升级回滚、最终交接。

## 非目标

未经验证的“防封成功率”宣传；以未申请的系统扩展权限补齐承诺。

## 当前证据

读取前序阶段所有验证报告与 progress；未验证的平台/入口不可写入发行支持清单。

已实现本地 `.app`/DMG 打包、结构校验与正式发行自动化入口：`Scripts/package.py`、`Scripts/package-dmg.py`、`Scripts/validate-app-bundle.py`、`Scripts/validate-dmg.py`、`Scripts/release.py`。发行脚本执行 Developer ID 签名、公证、staple、Gatekeeper 检查，输出拖放安装 DMG、ZIP 与双产物 SHA-256 manifest；签名或公证身份缺失时明确失败。当前机器只有 Apple Development 身份，尚无 Developer ID Application 身份，因此真实签名、公证与 Gatekeeper 发行门禁仍未通过。

本地打包现在分别生成 arm64 与 x86_64 的 macOS 13+ App、CLI、Agent 和特权 helper，再合成为 universal2；校验器逐一拒绝缺少任一架构的二进制。DNS System Extension 仍要求 macOS 15+。通用切片由本机构建与包结构检查验证，不代表 Intel 实机兼容门禁已通过。

2026-11-14 从当前工作树源码构建 universal2 build 52，App/DMG validator、DMG 完整性校验、发行包安装/升级/卸载生命周期和 Rosetta x86_64 Agent/CLI IPC 均通过。DMG SHA-256：`8d312cbad257da543f42632204991493cbbbba80687a8d4d48ea92a1c239aa06`。产物位于 `/tmp/SafeClaude-continuation-20261114-build52.app` 与 `.dmg`，均未签名；不作为正式发行包。

后续 build 53 纳入按钮样式遵守“减少动态效果”的改动。`swift test` 286 项通过；universal2 App/DMG validator、`hdiutil verify` 与随包安装/升级/卸载验收通过。DMG SHA-256：`1188f51ac1a53ac686121bc5d3d83210bb782b5be47f8ad85085743409107fb6`。产物 `/tmp/SafeClaude-reduced-motion-20261114-build53.app` 与 `.dmg` 未签名；仍不是正式发行包。

build 54 纳入 ProxyCheck 默认关闭的独立用户授权、无 key 匿名请求及其隐私披露。全量 Swift 测试 289 项通过；universal2 App `/tmp/SafeClaude-proxycheck-consent-20261114-build54.app` 通过 bundle validator、包内安装/升级/卸载夹具及 Rosetta x86_64 Agent/CLI IPC；DMG `/tmp/SafeClaude-proxycheck-consent-20261114-build54.dmg` 通过 DMG validator 与 `hdiutil verify`。DMG SHA-256：`7fd37f5cf947447694d94ec0f85a02fe0ca4bd765f1244ad8e66154425862e32`。App/DMG 未签名。真实供应商调用未执行；授权关闭行为由实现门控和策略/缓存单元覆盖验证。签名、公证、UI 实机与系统扩展授权验收仍未完成。

build 55 将 ProxyCheck 匿名查询方 IP 计数与 keyed 查询最长 24 小时保留披露加入实际授权控件。全量 Swift 测试 289 项通过；App `/tmp/SafeClaude-proxycheck-consent-20261114-build55.app` 通过 bundle validator、隔离包内安装/升级/卸载与 Rosetta x86_64 Agent/CLI IPC；DMG `/tmp/SafeClaude-proxycheck-consent-20261114-build55.dmg` 通过 validator 和 `hdiutil verify`。DMG SHA-256：`5c910e3867d0854331e45f98de5a26b2bcaa303ee2e32a47c05895ae5346b1fe`。对最终 build 55 执行 40 次真实本机 Agent/launcher 启动预检：常驻 Agent 热路径 40/40 按合成 TLS 风险阻断，中位数 35.0 ms、p95 37.6 ms；每次新建 Agent 的冷路径 40/40 阻断，中位数 51.3 ms、p95 55.8 ms；均远低于 2.5 秒门槛。未使用凭据或提交模型请求。DNS System Extension `xcodebuild analyze` 成功；Python compileall、plist lint、`git diff --check` 通过。build 55 未签名；两小时空闲资源测量仍运行中，签名/公证/UI 实机/系统扩展授权门禁仍未完成。

针对 build 55 再次尝试通过桌面自动化宿主连接本机菜单栏 App，宿主返回 `timeoutReached`；没有窗口或辅助功能树证据。未更改 TCC 权限，UI 视觉、键盘与 VoiceOver 门禁继续保持未验收。

build 56 调整菜单栏底部操作布局：主检测按钮单独占行，集成、规则与设置次操作均有图标和可见文字。全量 `swift test` 289 项通过；universal2 App validator、发行包安装/升级/卸载、setup 事务回滚/并发编辑保护、Rosetta IPC 与 DMG validator/`hdiutil verify` 均通过。DMG SHA-256：`61690ae275e07e11c058c3ad2fb2756056f9cd8b31cad9cf483ef6bb496d3359`。该改动基于源码审查；桌面 host 仍 timeout，实际画面/键盘/VoiceOver没有实测证据。build 56 未签名。

build 57 将菜单面板调至 420×650pt，辅助功能字号下 460×760pt，与界面规范尺寸一致。全量 `swift test` 289 项通过；App validator、发行包安装/升级/卸载、隔离 setup 回滚/并发编辑保护、Rosetta IPC、DMG validator 与 `hdiutil verify` 通过。DMG SHA-256：`c8d2ee979ba18f57e1217932161e8e2a23536f7006070b2396568848025effb0`。build 57 的 universal Agent 与 build 56 Agent 字节完全一致（SHA-256 `b138fa062cd87041e4b4cc119015bd1426a62f1f7ec19acbf40a4c3c137cdc72`），因此 build 56 上正在进行的两小时 Agent 资源样本覆盖相同 Agent 二进制。build 57 未签名。

对 build 57 的桌面 UI 宿主复试返回 `timeoutReached`，仍没有运行窗口或辅助功能树证据。

## 当前工作树复验（build 58，2026-11-14）

从当前源码构建 universal2 build 58 `/tmp/SafeClaude-continuation-20261114-build58.app` 与 DMG。Swift 测试 289 项全部通过；App/DMG validator、`hdiutil verify`、随包 install/upgrade/uninstall（保留用户设置、不依赖系统 Python）、Rosetta x86_64 Agent/CLI IPC（64 项状态）均通过。DMG SHA-256：`11d0a8ebca52b6bf76af69be6c32108e0c13d6b65b312480a68a0b64e5e25a25`。对当前源码的 `SafeClaudeDNS` Release `xcodebuild analyze` 成功。

build 58 的菜单栏 Agent SHA-256 与 build 56 相同（`b138fa062cd87041e4b4cc119015bd1426a62f1f7ec19acbf40a4c3c137cdc72`），因此 build 56 当前两小时测量覆盖 build 58 Agent。build 58 的桌面 Computer Use 连接仍返回 `timeoutReached`。钥匙串当前只有 Apple Development 身份，`SafeClaudeNotary` 凭据 profile 不存在；build 58 未签名、未安装。真实 UI/键盘/VoiceOver、Developer ID/公证/Gatekeeper、DNS System Extension 实机授权与真实数据路径、睡眠唤醒和干净系统演练仍未关闭。两小时 Agent 基准仍运行中，详见 `progress.md`，不提前记为完整样本。

新增 `.github/workflows/macos-ci.yml`，在 GitHub Actions 执行 Swift 测试、DNS System Extension 静态分析、plist/entitlements lint、隔离启动/网络/受管会话唤醒/官方 wrapper 拒绝处置/资源基准强杀失败/安装/ENOSPC 夹具、universal2 App/DMG 构建和包内生命周期验证。App bundle validator 后另运行包内 Release Agent 30 秒资源/正常关闭冒烟检查。资源基准故障夹具以写入 2 MiB stderr 且忽略 SIGTERM 的假 Agent 验证强杀会使样本失败，并确认日志尾部可读且子进程未被未消费管道阻塞。独立审查修正两项 CI 可靠性问题：格式检查现在比较实际 PR/push 提交范围；本地候选 App 与 DMG 先进入保留可执行权限的 tar.gz 再上传。用含可执行 App 的 build 58 实际做过打包/解包往返并重新通过 App/DMG validator 与 `hdiutil verify`。GitHub hosted runner 尚未实际执行。

## 当前工作树续验（build 59，2026-11-14）

新增 Debug-only 唤醒通知 IPC 与受管会话夹具。隔离 Agent 收到合成 `NSWorkspace.didWakeNotification` 后使网络代次失效，触发 F04 重评，并只中断身份匹配的受管会话；旁观进程保持运行，未发送模型请求。真实 Claude Code 官方 `processWrapper` 唤醒场景也通过。全量 Swift 测试 289 项通过。universal2 build 59 `/tmp/SafeClaude-wake-20261114-build59.app` 的 App/DMG validator、包内 install/upgrade/uninstall、设置保留、无系统 Python、Rosetta x86_64 Agent/CLI IPC（64 项状态）与 `hdiutil verify` 均通过；DMG SHA-256：`b8ab614438b11ef43a90a15d624846213aa66a89639c1c202784a716c212ffdd`。Release Agent 已确认不含 Debug 唤醒 IPC 字符串。

build 56 两小时 Agent 样本不能覆盖 build 59：前者 SHA-256=`b138fa062cd87041e4b4cc119015bd1426a62f1f7ec19acbf40a4c3c137cdc72`，后者=`b5b6e9608a5b43b9532c7af575162a091eaaa827eaca56232d85ae4676a09f45`；Mach-O 差异除架构 UUID 和签名散列外还涉及签名区外字节。build 56 长测仍运行中，结束后需以 build 59 单独补测。CI YAML 和内嵌 Bash 语法已复核；GitHub hosted runner 尚待实际运行。

随后从当前工作树复验 build 59：`swift test` 289/289 通过；App/DMG validator、`hdiutil verify`、Python compileall 与 `git diff --check` 通过。CI 中所有隔离运行夹具在本机通过，含真实临时卷 ENOSPC；包内 install/upgrade/uninstall、Rosetta x86_64 Agent/CLI 64 项 IPC、DNS Extension Release 静态分析和 plist/entitlements lint 通过。此次桌面实测再次只能取得 macOS 锁屏画面，未获得应用窗口或 VoiceOver 树。

build 59 的 Release Agent/CLI 热、冷启动门禁各完成 40 次。常驻 Agent 热路径 40/40 在预检中阻断，中位数 24.4ms、p95 27.6ms、最大/首样本 56.7ms；每次创建全新隔离 Agent 的冷路径 40/40 阻断，中位数 47.8ms、p95 49.4ms、最大 52.0ms。两组均低于 2.5 秒预算，确认使用 build 59 包内 Agent/CLI 且不含 Debug fixture IPC；未读取凭据或发起模型请求，SIGTERM 清理全部正常。

长时基准脚本改为将 Agent stderr 写入隔离临时文件，避免未消费管道在 Agent 连续写日志时填满并阻塞被测进程；失败诊断只读取末尾 4 KiB。build 59 Release 30 秒冒烟样本 14 个区间，CPU 均值/p95 0.283%/0.989%，RSS 均值/峰值 15.05/15.14 MiB，SIGTERM 正常结束且未升级 SIGKILL。当前 build 56 长测是旧脚本启动的进程，保持运行至自然结束；下一次 build 59 两小时测量使用修订后的日志处理。

## 设计与实施方案

在干净用户环境验证安装授权、Agent 生命周期、Claude 官方升级、自身升级、卸载和恢复。通过 Developer ID 公证打包，校验 app/helper/launcher 版本与签名。

签名凭据不可用时先完成所有可做的构建和校验，并真实标记发行阻断，不声称发布完成。规则远程更新若未纳入首版，则保持内置版本；若启用，则必须完成签名/到期/未来生效/回滚与不含任意代码的检查。

## Todo

- [x] 完成隔离故障注入：Agent crash/restart、journal/G02 损坏、Agent 离线、供应商/代理路径和受管会话策略/网络/唤醒通知处置均通过；合成进程与本机真实 Claude 官方 wrapper 场景均只中断身份匹配的受管会话。`disk_pressure_fixture.py` 在临时 HFS+ 卷注入 ENOSPC，确认 G02 与 SessionJournal 写入 fail closed、Agent 保持存活、用户卷未改动。
- [ ] 在真实硬件上验证睡眠唤醒后的网络变化采集、重评负载和受管会话处置；通知夹具不替代硬件睡眠/唤醒。
- [x] 完成 build 59 Release 启动预检时延门禁：常驻 Agent 热路径与每次新建隔离 Agent 的冷路径各 40 次、40/40 按预期阻断且低于 2.5 秒。热路径中位数/p95 为 24.4/27.6ms；冷路径为 47.8/49.4ms。均核对 bundle build number、Agent/CLI 无 Debug fixture IPC；冷路径计入 Agent 进程创建，两组 SIGTERM 清理正常。
- [ ] 完成 build 59 长时和活跃负载验收：15 分钟/1 小时单机空闲 CPU/RSS 基线见 `docs/validation/phase-04/agent-resource-baseline-2026-11-14.md`。build 51 两小时旧样本关闭方式缺失，只保留观察数据；build 56 两小时样本仍运行中（约 93 分钟），覆盖 build 56–58 的相同 Agent 二进制，不覆盖 build 59，结束后以修订后的日志采集脚本对 build 59 做完整两小时 CPU/RSS/正常关闭测量。繁忙网络、持续 Claude 活跃期请求负载和真实硬件睡眠唤醒后的负载仍未测全。
- [x] 隐私静态与落盘验收：发行包和当前用户 SafeClaude 状态文件未命中常见 API/token、私钥 PEM、Bearer token、原始 IP 字面量或聊天字段；专属日志目录不存在。诊断报告通过生产写入器落盘测试，验证 `0600`、原子替换、不跟随目标符号链接，以及注入的凭据、聊天、路径、代理密码和 IPv4/IPv6 地址均未写入。实际 NSSavePanel 交互与真实桌面用户导出的单独复扫仍受 UI 会话验收限制。
- [ ] 在干净系统演练官方升级与全系统回滚。发行包 install/upgrade/uninstall 隔离夹具已通过；当前用户 GUI launchd 域中已用隔离临时 HOME 验证 Agent 启动和 SIGKILL 自动重启；真实安装器注册、干净系统升级回滚仍未验证。
- [ ] 用 Developer ID 身份和 notarization profile 完成真实签名、公证、staple 与 Gatekeeper 验证。
- [x] 完成本地试用故障手册与支持边界入口（`docs/operations/troubleshooting.md`、README 和阶段 01 兼容矩阵）；正式发行说明仍需在签名发行版本确定后编写。
- [ ] 按最初目标复核功能，不以最近一次 UI 演示替代最终验收。

## 测试方案

真实设备端到端测试与独立复核；固定版本和机型，记录样本数量、失败次数、p95。运行阶段 01–03 的必要回归集，新增故障才扩大测试。

重点验证 Agent 故障期间已有会话保护缺口被明确显示；超时不会偷偷启动；卸载不删除用户后续配置；不依赖登录 X/Net.Coffee 页面才能启动产品。

## 输出契约

`docs/validation/phase-04/` 包含性能报告、隐私检查、打包校验、回滚/卸载记录；产出带版本与校验值的发行包或明确列出凭据导致的待发行状态。

## 完成门禁

最终完成条件逐条有证据；性能目标达成或偏差经记录评审；签名/公证完成才标记可正式发行；支持清单与真实测试一致，已知问题可见。

## 交付物

发行包、校验值、发布/升级/卸载手册、支持矩阵、验收报告和长期进度最终验收。
