# 阶段 02：核心评分与启动防护

## 阶段目标

受保护 `claude` 启动经过 Agent 生成可解释决策，允许后保持官方 CLI 行为，失败时可逆且机器可识别。

## 进入条件

阶段 01 门禁通过，支持矩阵与待验证例外已落盘。

## 范围

Swift package/工程结构、确定性规则、持久化、IPC、用户级 Agent、launcher、PATH shim、官方 wrapper 配置与 doctor。

## 非目标

完整菜单栏视觉、系统级强制控制、云服务和自动分析账号内容。

## 当前证据

以阶段 01 的 `docs/validation/phase-01/` 为真实契约；不得只按官网声称兼容。

## 设计与实施方案

按产品设计建立共享 `GuardCore`、`GuardProtocol`、`NetworkProbe`、`GuardAgent`、`GuardCLI` 模块。规则输入与副作用解耦；输出 SafetyResult、安全分上界和完整度。策略、快照、ticket 绑定版本和 networkEpoch。

Unix socket 限制权限和消息长度，验证 peer；不传完整 env。预登记 exec 身份，禁止可继承 bypass。当前历史使用版本化 JSON；文件边界、原子写入、保留上限与历史损坏时的 unknown/hold 由实现和回归覆盖。

安装器只修改自身 PATH 标记与经过合并的用户 wrapper 设置；存在企业 wrapper 冲突时不覆盖。doctor 给出覆盖清单和恢复方式。

## Todo

- [x] 实现 64 项目录、配置解析、context、逐项扣分/去重、低于阈值阻断、时间与未知语义；持续采集缺失项仍按矩阵保持 unknown/hold。
- [x] 实现 IPC、缓存/in-flight 合并和短 ticket。
- [x] 实现 exec 启动、嵌套入口、错误码与 stdout 透明性。
- [x] 实现 Agent 注册、启动健康和用户授权状态；需系统批准的服务状态在未批准时保持明确待处理/hold。
- [x] 实现安装、配置备份、冲突提示、doctor 与卸载恢复；干净系统和真实 launchd 域仍需发行验收。
- [x] 实现脱敏本地历史与有界、原子持久化。存储使用版本化 JSON（不是 SQLite，也不是整体加密）：上下文与出口地址使用 Keychain 中的本地 HMAC key 做摘要；国家码、采样时间及有限风险标记在当前用户专属目录中以 `0600` 文件保存。当前产品无旧数据库需迁移，阶段 04 继续跟踪实际文件隐私。相关实现为 `Sources/GuardCore/HistoryTracker.swift`，故障写入回归见 `Tests/GuardCoreTests/HistoryTrackerTests.swift`。

## 测试方案

边界测试：79/80/89/90、轻项累计、IP/时区与 IP/语言分别扣分、过期、networkEpoch 改变、未来规则未生效、重复证据、历史不足。检查失败产生扣分/hold，不能按 0 扣分通过。IPC 测试：非法 peer、超大包、连接断开、并发启动、服务不在。exec 测试：argv 空格/特殊字符、pipe、交互 stdin、JSON stdout、cwd、信号与退出状态。

安装回归：原链接不变；用户已有设置与安装后新增修改在卸载后保留；官方升级到新路径后重新发现；嵌套不会死锁/免检。

## 输出契约

可构建 Agent/CLI、可复跑测试、`guard status --json` 与 `guard doctor` 协议说明；证据保存 `docs/validation/phase-02/`。

## 完成门禁

失败状态没有漏放；成功无多余 stdout；凭据/聊天正文不进入数据；安装升级卸载恢复通过；阶段 01 已支持入口无退化。

## 交付物

核心模块、用户级后台、启动器、集成管理命令、测试与运行契约。
