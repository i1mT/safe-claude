# SafeClaude 试用与排障手册

本文适用于当前本地评估版。正式签名发行和干净系统验证完成前，请在可恢复的开发环境试用。

## 启动被阻断

SafeClaude 在安全分低于策略门槛、检查项关键状态未知/过期，或后台服务不可用时会拒绝执行 Claude。终端入口返回状态码 `75`，错误写入标准错误，不会把诊断内容混到 Claude 的标准输出。

先在菜单栏查看安全分、待确认数和具体规则。修复对应网络、代理、地区设置或后台授权后，等待下一次检查；SafeClaude 不会自动重开被阻断的会话。不要通过直接调用 Claude 原始二进制绕过阻断。

## Agent 离线或状态过期

打开 SafeClaude 菜单栏面板确认是否正在检查。App 会尝试启动随包 Agent；Agent 恢复前受管启动继续阻断。终端可运行：

```sh
safe-claude status
safe-claude doctor
```

`status` 返回 Agent 的当前状态 JSON；`doctor` 检查 Agent 是否在线、当前 PATH 是否选中 SafeClaude shim，以及 App/Agent 规则资源是否存在。`doctor` 退出码 `75` 表示检查未通过。它检查当前命令环境，不验证 shell alias、IDE、自动化或其他未纳入的入口。

若 Agent 仍离线，先从菜单栏选择“重新检查”；再检查 macOS 登录项设置中 SafeClaude 是否允许后台运行。若问题持续，重新打开完整的 SafeClaude.app。后台服务、关键状态文件损坏或检查数据过期时，产品按设计继续 hold。

## Claude 未经过保护入口

运行：

```sh
safe-claude doctor
```

确认 `shimInstalled` 与 `shimSelectedByPATH` 均为 `true`，`agentOnline` 和规则资源状态有效。检查失败时，在 App 的“Claude Code 接入”窗口重新扫描并选择真实 Claude 可执行文件，然后查看安装器报告。

`doctor` 的 `scope` 是当前进程；它不会证明所有 IDE、shell alias、绝对路径或自动化入口都经过包装。已集成入口之外的启动不能被该命令推断为受保护。

## 首次接入或升级失败

优先通过 App 的“Claude Code 接入”窗口执行安装或升级。若窗口报告配置已被修改、存在活动会话或服务状态不明，请保留现状并按提示处理；安装器会在这些情况下停止，不覆盖用户改动。

开发 checkout 可用隔离夹具验证安装器行为：

```sh
python3 Tests/Fixtures/setup_integration_fixture.py
```

此夹具操作临时 HOME 和模拟的 launchd 服务，不会修复或重写当前用户的安装。

## 卸载失败

通过 App 的“Claude Code 接入”窗口选择完整移除。卸载会先停止新启动并确认没有受管会话，再撤销 SafeClaude 的 DNS 扩展、校时服务和状态快照，最后清理 SafeClaude 自己添加的 shell、Claude settings 与用户服务。

若 macOS 要求重启、系统服务尚未批准、配置被编辑或状态无法核验，卸载会保留安装组件，供修复后重试。不要手动删除保留的 bundle 或服务文件；先按 App 显示的具体状态恢复授权或配置。

## 导出诊断与隐私

“数据与诊断”页面可手动导出脱敏 JSON。导出只包含白名单中的版本、状态、分数、未知数量和规则摘要，不包含自由文本原因、IP、代理凭据、路径、启动票据或 Claude 会话内容。文件仅当前用户可读写。

导出前应确认当前检查状态有效。请勿在报告中附加 Claude 登录凭据、聊天内容或项目源码。供应商诊断可能向已配置的第三方发送出口 IP；菜单设置和 README 会说明各供应商的数据用途。

## 当前评估版边界

- 本地 App/DMG 结构和隔离安装生命周期已通过；该包未签名、公证。
- 运行数据目录、系统日志和实际导出文件的整机隐私检查未完成。
- DNS System Extension 与特权校时服务仍需已签名发行环境完成真实授权验收。
- Intel、macOS 13 干净系统、长时运行、磁盘满、真实睡眠唤醒和网络恢复仍需目标设备验收。
- 目标桌面当前不可交互时，不能据此宣称菜单栏视觉、键盘或 VoiceOver 验收通过。
