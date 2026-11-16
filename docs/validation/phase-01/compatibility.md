# Claude Code 与网络兼容记录

验证更新：2026-11-14（Asia/Shanghai）。主机：macOS 15.6、Apple Silicon；本机原生 Claude Code 为 2.1.323。仅列出可复跑的观察，其他版本不能自动继承本表结论。

| 场景 | 状态 | 证据 / 范围 |
|---|---|---|
| 真实 Claude 前台请求 | 已验证 | `claude_runtime_fixture.py`，临时 HOME、临时配置、合成 key 和 loopback HTTP 模拟 API，未访问真实模型 |
| 后台 self-spawn 的官方 wrapper | 部分验证 | 本机真实 Claude 2.1.323 夹具触发 `CLAUDE_CODE_PROCESS_WRAPPER` 并通过 SafeClaude 子进程门控；没有覆盖全部 self-spawn 深度与内部入口 |
| wrapper 拒绝 | SafeClaude 子进程拒绝/祖先处置已验证；顶层入口覆盖部分验证 | `wrapper_agent_rejection_fixture.py --real-claude` 验证本机 Claude 2.1.323 的官方 `processWrapper` 调用 SafeClaude launcher，Agent 拒绝子进程并结束身份匹配的 Claude 顶层进程；未登记的并行进程保持运行。夹具通过隔离 IPC 预登记父进程，未覆盖所有真实顶层启动入口 |
| F04 运行策略变化处置 | 已验证真实 Claude 受管会话链路 | `managed_generation_fixture.py --real-claude` 让 Claude 通过官方 wrapper 启动并停在本机隔离门闸，修改运行门槛后确认 Agent 触发 F04、结束 Claude 父会话且保留旁观进程；没有发送模型请求。`--real-claude --network-change` 通过仅 Debug 的 IPC 推进 Agent 网络代次，验证同一会话退出链路。规则状态由 Debug fixture assessment 注入；真实 OS 路由变化如何进入代次仍需单独验收 |
| 终端 PATH shim、IDE、绝对路径、深链接、Remote Control/teams | 集成代码和隔离安装夹具已验证；真实入口覆盖未完整验收 | 安装夹具验证 shim、用户配置保留及卸载；PATH 顺序、shell hash、GUI IDE 继承和显式绝对路径覆盖仍需真实宿主逐项验收。深链接、Remote Control/teams 不在当前支持范围 |
| universal2 x86_64 Agent/CLI | Apple silicon 上 Rosetta IPC 已验证；Intel 实机未验证 | `rosetta_integration_fixture.py --app /tmp/SafeClaude-design-20261114-build40.app` 用 x86_64 切片启动 Agent 和 CLI，经隔离 socket 取得完整 64 项状态；不涵盖 Intel 主机的系统扩展、LaunchDaemon 或 macOS 13 服务行为 |
| macOS 其他版本 / 其他 Claude 安装渠道及版本 | 未验证 | 未在本机制造替代安装 |
| 真实 Claude HTTP 代理和 NO_PROXY | 已验证 | 2026-11-14 重跑 `claude_proxy_runtime_fixture.py`：直连、HTTP_PROXY、NO_PROXY、大小写冲突和 settings/进程变量组合均命中预期 loopback 接收端，Claude Code 2.1.323 |
| 真实 Claude HTTPS CONNECT、NO_PROXY、大小写 | 已验证 | 2026-11-14 重跑 `claude_tls_runtime_fixture.py`：临时证书及两个本地代理；CONNECT、NO_PROXY、大小写冲突、用户/项目/local settings 优先级均命中预期代理，Claude Code 2.1.323 |
| 用户 / 项目 / 项目 local settings | 部分验证 | HTTP 与 HTTPS loopback 夹具确认各作用域对实际 Claude 请求路由的影响；托管配置及 SafeClaude 在线 trace 与真实企业代理配置的组合仍未验证 |
| 目标分流与地理查询代理 | 部分验证 | `proxy_fixture.py` 和 `geo_proxy_fixture.py` 测试 Swift 探测代码 + 系统 curl；这些不证明 Claude 的所有目标配置等价 |
| 系统代理 / PAC、企业 CA / mTLS、SOCKS、ALL_PROXY | 未适配 | 发现不可等价配置时保持 unknown，系统代理启用状态尚未在真实机器端到端验证 |
| IPv4 / IPv6 | 部分验证 | 返回地址族与限制校验有单元测试；经代理不能控制目标出口地址族，保持 unknown |
| exec 透明性 | 模拟目标已验证 | `exec_fixture.py` 检查 PID、参数、cwd、stdin/stdout、环境和退出码；未验证实际 Claude 的所有 TTY/信号场景 |
| 本机 Agent + launcher 启动预检时延 | 已测隔离阻断路径，不代表所有在线评估 | 2026-11-14 对 build 51 universal2 Release 的常驻 Agent 与每次新建 Agent 两组各完成 40 次预检，全部低于 2.5 秒。热路径中位数 24.7 ms、p95 26.8 ms、最大值/首样本 63.8 ms；冷路径中位数 47.8 ms、p95 50.5 ms、最大值 51.3 ms。夹具核对 bundle build number 并确认 Agent/CLI 不含 Debug fixture IPC 动作；冷路径计时包含 Agent 进程创建。若清理需将 SIGTERM 升级为 SIGKILL，夹具失败。每次以合成 TLS 降级信号在模型请求前确定性阻断，不包括完整在线信誉供应商请求或模型请求，也不替代多代理/IPv6/系统代理、繁忙网络或唤醒后负载样本 |
| 菜单栏与集成界面 | 未取得实机可视/辅助功能验收 | 原生 App 可构建并启动；当前 Computer Use host 返回 timeout，未拿到目标窗口/AX 树，不能据源码或 bundle 构建宣称视觉、键盘或 VoiceOver 通过 |

所有夹具使用临时配置与合成数据；不修改用户现有 Claude 配置，不读取登录凭据。
