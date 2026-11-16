# 阶段 01：本机验证记录

2026-11-11；macOS 15.6（24G84）、Apple Silicon、Xcode 26.0.1、Swift 6.2、Claude Code 2.1.319。该记录随实验补充，动态进度见长期计划。

## 启动与进程

| 场景 | 验证结果 |
|---|---|
| 官方版本 | `/Users/iimt/.local/bin/claude --version` 输出 2.1.319 |
| 官方 launcher 设置 | 独立临时 `CLAUDE_CONFIG_DIR` 和 `CLAUDE_CODE_PROCESS_WRAPPER` 下，`claude daemon status` 显示已解析指定 launcher，daemon 未运行 |
| 无凭据 `claude agents` | 返回 1；后台服务未启动，launcher 未调用 |
| 合成凭据 + 封闭本地代理的隔离 PTY | 未触发 launcher；没有后台服务；实验结束后执行独立配置的 stop |
| 测试目标的 `execv` | `python3 Tests/Fixtures/exec_fixture.py` 验证 PID、argv、cwd、环境、stdin、stdout 与退出码均保留 |
| wrapper 拒绝行为 | `claude_wrapper_rejection_fixture.py`：wrapper 拒绝时顶层后台命令在 6 秒观察期内未退出，不能将 wrapper 返回视作即时错误反馈 |
| SafeClaude Agent 处置官方 wrapper 拒绝 | `wrapper_agent_rejection_fixture.py --real-claude`：本机 Claude Code 2.1.323 后台入口调用门控 wrapper；释放后通过官方 `Scripts/integration/process-wrapper` 和真实 SafeClaude launcher 进入 Agent，子进程检查返回 75，已登记的 Claude 顶层进程按 PID/UID/出生时间复核后收到 SIGINT 并退出；同机并行的未登记进程保持运行。该夹具通过 Debug-only IPC 登记已启动会话，验证拒绝/处置段，不覆盖真实顶层 preflight 的 allow 流程或全部 Claude 入口 |
| SafeClaude 对真实 Claude 启动前阻断 | `agent_integration_fixture.py`：Claude Code 2.1.319 在独立临时 HOME、配置与 Agent 下，经 SafeClaude launcher 执行 `claude --version`；设置 `NODE_TLS_REJECT_UNAUTHORIZED=0` 后返回阻断码 75，Agent 报告 D05 为 triggered。未提交模型请求，Claude 可执行文件没有运行；启动结果在随后的 Agent 状态中可见 |
| 启动预检端到端时限 | `preflight_latency_fixture.py`：隔离 Agent、真实 launcher 和 Claude Code 2.1.319；10 次启动上下文均经规则状态确认 D05 triggered 并在执行 Claude 前阻断；首样本/p95 34.2ms、中位数 20.7ms，10/10 低于 2.5 秒。样本仅覆盖当前 Mac、无凭据临时 HOME 和本次直连/网络状态，代理、IPv6、系统代理及冷启动网络组合需继续测量 |
| DNS 配置变化检测 | `SystemFingerprintTests` 验证 resolver 输入变化产生不同 HMAC 摘要且摘要不含原 DNS 地址；三次不同路由摘要会触发 C08。C08 现要求连续完整采样 10 分钟且变化少于三次才通过；采样间隔超过 10 秒、最近一次样本超过 5 秒、Agent 醒来或密钥轮换都会清空通过窗口。Keychain 派生密钥下的摘要和单调时间戳在 Agent 重启间保存。尚未改变本机 DNS，也未验证真实 Claude 进程的实际 resolver 选择或泄漏 |
| 真实 supervisor 启动 | `python3 Tests/Fixtures/claude_runtime_fixture.py`：隔离配置、本地模拟 API 和合成凭据下，后台启动调用了官方 wrapper；完整嵌套链仍未验证 |
| IDE、深链接、tmux、旧版 Claude | 尚未在真实环境验证 |

上述 Claude 实验未发送模型请求，未读取用户凭据，也未修改用户的 Claude 配置。

## 网络与配置

- `python3 Tests/Fixtures/proxy_fixture.py` 建立仅绑定回环地址的临时 HTTPS 目标和 CONNECT 代理，使用临时自签 CA。已验证 TLS、代理路径、凭据脱敏、`NO_PROXY` 直连、同一环境下 API/认证两个域名走不同路径。
- 夹具已编译并调用 Swift TraceProbe，再经真实系统 curl 验证本地 TLS、CONNECT 和 NO_PROXY；临时 curl 配置不影响结果。不能把这项实验误写为 Claude runtime 的端到端验证。
- 环境级无登录 trace 实验取得 `claude.ai`、`claude.com`、`api.anthropic.com`、`platform.claude.com` 的出口观测，实验当时一致；这不是针对 Claude 进程的最终上下文验证。Swift `TraceProbe` 已能对目标执行环境级诊断。
- 独立审查指出 curl 用户配置、代理地址族、TLS 配置冲突及输出管道超时问题。探测现以 `-q` 禁用 curl 配置，指定目标地址族的代理探测返回 unknown，检查两个配置来源的非空 TLS 值，读取设总时限及大小上限；针对性测试通过。
- `ProxyConfiguration` 按官方文档实现四个 HTTP(S) 代理变量的顺序；`ALL_PROXY`、不支持的 bypass 语法与互相冲突的 `NO_PROXY` 返回 unknown。代理变量大小写冲突只暴露变量名，不输出密码。
- `python3 Tests/Fixtures/claude_proxy_runtime_fixture.py` 和 `claude_tls_runtime_fixture.py`：Claude 2.1.319 使用临时配置和本地模拟 API 验证了 HTTP、HTTPS CONNECT、NO_PROXY、大小写优先级、同名用户 settings 覆盖进程环境，以及项目 settings 覆盖用户、项目 local 覆盖项目 settings。托管设置和其他版本仍待验证；同名配置来源冲突当前保守返回 unknown。
- `LocalEnvironmentSnapshot` 能采集本机和调用方提供的进程环境中的时区、locale、代理状态；仅输出代理变量名、类型和来源，不保留代理地址及凭据。与 Claude runtime 的实际等价性尚待验证。
- 以本机 Node 24 的 `Intl.DateTimeFormat` 验证 `LANG`、`LC_ALL` 和 `TZ` 的样例；Claude Code 自带 runtime 不等同于该实验。
- 生产候选 IP 信誉服务：`ipapi.is` 文档说明 keyed POST 支持 `ips` 批量 JSON，`is_abuser` 表示近期滥用，`is_proxy=true` 表示已知公开代理；文档在 2026-11-06 更新后明确这些安全 detection 字段需要 API key。现已接通 keyed POST、Keychain 保存、目标出口 IP 精确绑定、按 key/路由隔离的 6 小时内存缓存和 B02/B03 评分。`is_proxy=false` 只表示未命中已知开放代理，不能排除住宅/移动代理，因此 B03 仍 unknown；无 key 时 B02/B03 也不会把空字段当通过。官方开发者文档：<https://ipapi.is/developers.html>。
- 系统时区从 `/etc/localtime` 读取，进程 TZ 不影响系统基线；不可读时返回 unknown。国家语言候选基于 Unicode CLDR 48 官方语言与至少 5% 人口使用语言生成。
- 2026-11-12：IPWho 的免费地理接口可达；真实 API 目标出口地址查询成功并验证返回 IP，获得国家、时区和 ASN。`IPWhoGeolocation` 已在线解析；最初用 Swift URLSession 验证可达，当前采用经过目标域名代理解析的 curl 传输；该来源不提供本适配器使用的信誉标签，信誉仍为 unknown。地理查询使用按 IPWho 目标解析的环境代理及 NO_PROXY；本地 TLS/CONNECT 夹具通过。发现系统代理或 PAC 则返回 unknown，未验证这些路径。官方文档称免费端点允许商用、每客户端 IP 每日 1000 次、无安全信誉字段；正式接入仍需设计缓存、429 和用户授权体验。
- 本机对 `https://api.ipapi.is/?q=32.43.11.44` 的早期 GET 测试遇到 TLS unexpected EOF。当前改为文档支持的 JSON POST，并通过本地 fake-curl 集成验证代理路由、body 管道与 argv/临时 curl 配置脱敏；仍未配置个人 key 或取得实际 keyed 服务响应，因此供应商在线可用性与授权额度仍未完成实测。
- `is_vpn` 按其文档的 truthy 语义解析；其他非布尔值或缺失字段维持 unknown。
- 2026-11-14：ProxyCheck v3 现采用默认关闭的独立用户授权。关闭时评估器不创建 ProxyCheck 请求；开启后可匿名查询，无 key 的失败结果按 15 分钟退避，避免消耗供应商每日额度。缓存身份区分匿名/keyed，并继续绑定出口 IP 与 Claude 实际网络路由；API key 不进入请求 URL 参数、持久缓存或诊断输出。设置披露匿名查询会将待查公网 IP 发送给 ProxyCheck，供应商隐私说明匿名查询记录查询方 IP 以计算额度，keyed 查询最多保留 24 小时；用户可选保存 key 于 Keychain。授权、旧策略默认行为、匿名 HTTPS 请求和匿名/keyed 缓存隔离均有 Swift 回归覆盖。未向真实供应商发送请求。供应商来源：官方 API 与额度说明、官方隐私说明（2026-11-14 复核）。

## 地区规则快照

- [地区政策数据](../../../DataSources/region-policy-2026-11-12.json)记录官方来源、读取时间、保守生效时间和 30 天复核期限。官方只给出日历日期，代码等该日期在所有时区开始后才启用快照；过期自动保持 unknown。
- 官方明确支持的国家与明确不在清单的独立国家有检测；乌克兰因存在地区例外、未列明的属地因需确认归属而保持 unknown。目标 trace 的国家与地理供应商冲突时先 hold。

## 用时

`swift build -c release && python3 Scripts/benchmark-probe.py` 在上述机型下，40 次本地 `probe-config`：首样本 7.34ms，中位数 4.62ms，p95 6.49ms，最大 7.34ms。仅衡量本地配置诊断，**不包含** daemon IPC、网络探测和实际 launcher 的完整启动路径。

2026-11-12 连续 5 次 `assess-current --ipwho`：1280.1、912.3、846.1、928.3、884.6ms，中位数 912.3ms，均返回 hold。只覆盖一个 API trace 和地理查询，不是完整启动前检查或 p95 指标。

## 后续门禁

1. [64 项采集矩阵](capability-matrix.md)中多数规则尚无生产采集器；逐项完成并验证。
2. 使用隔离环境验证真实 supervisor/self-spawn 和目标 Claude 配置优先级。
3. 选择可达、许可合适的信誉来源，验证真实响应与期限。
4. 实现与真实目标路径同上下文的探测；不能拿其他域名的 echo 结果代替目标出口。
5. 测量完整 preflight 的冷、热路径，并验证超时默认阻断。

详细支持范围和未验证入口见 [兼容记录](compatibility.md)。
