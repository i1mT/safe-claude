# safe-claude

macOS 菜单栏环境监测与 Claude Code 启动防护工具。安全分从 100 开始逐项扣减，越高越安全；默认保守阻断。当前正在实现和验证中：已有菜单栏、Agent、保守启动门和隔离安装原型，但检查采集尚不完整，当前默认阻断，暂不适合安装为日常使用的保护工具。

`safe-claude` 为仓库暂名，公开发行名称另行确定。

## 方案导航

- [调研报告与证据分级](docs/research/2026-11-11-findings.md)
- [产品与技术设计](docs/design/product-and-architecture.md)
- [评分和阻断契约](docs/design/scoring-and-policy.md)
- [64 项检测规则与初始扣分](docs/design/check-catalog.md)
- [界面与交互设计](docs/design/interface.md)
- [静态界面概念图](docs/design/menu-bar-concept.svg)
- [SafeClaude 图标方向比较](docs/design/logo-concepts/index.html)
- [界面概念图 PNG 预览](docs/design/menu-bar-concept.png)
- [实施计划与长期进度](docs/plans/2026-11-11/environment-guard/progress.md)
- [实施计划维护规范](docs/plans/2026-11-11/environment-guard/AGENTS.md)
- [试用与排障手册](docs/operations/troubleshooting.md)

研究日期：2026-11-11，Asia/Shanghai。权重、阈值与性能指标均为待验证的产品设计建议。

## 本地打包与正式发行

构建全新 checkout 前，先用 Python.org 的 Python 3.14.10 universal2 与 PyInstaller 6.22.3 生成随包安装器：`python3.14 -m pip install pyinstaller==6.22.3`，再运行 `python3 Scripts/build-setup-runtime.py --python /Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14`。运行时许可证和 PyInstaller、bootloader 及相关构建依赖的第三方声明随包提供于 `Resources/Installer/`；正式发行签名会由 `Scripts/release.py` 统一重签。随后用 `python3 Scripts/package.py --output /tmp/SafeClaude.app --version 0.1.0 --build-number 1` 构建未签名本地 `.app`；App、CLI、Agent 与特权 helper 会分别构建 arm64 和 x86_64 的 macOS 13+ 版本并合成 universal2，流程同时构建并嵌入 `SafeClaudeDNS.systemextension`（扩展目标 macOS 15+）。再用 `python3 Scripts/validate-app-bundle.py /tmp/SafeClaude.app` 检查架构和 bundle。DNS Proxy 需用户从 App 设置中主动请求 macOS 授权；扩展把身份绑定的短期 DNS 观测交给 Agent。D01–D03 已接入运行时检查；D04 读取目标域名适用的系统 DoH/DoT/明文设置，用户可跨会话要求任一加密协议、仅 DoH 或仅 DoT；不符合策略时扣分，会话降级基线可跨 Agent 重启恢复。首次观测和路由歧义仍保持未知并阻断，真实系统路由仍待实机验收。正式发行使用 `Scripts/release.py`，需要具备 Network Extension 与 System Extension 安装 entitlement 的 Developer ID 身份和已配置的 `notarytool` Keychain profile：

```sh
python3 Scripts/release.py --version 0.1.0 --build-number 1 \
  --identity "Developer ID Application: Example (TEAMID)" \
  --notary-profile safeclaude-notary
```

正式发行脚本会签名、验签、公证并 staple App、ZIP 和拖放安装 DMG，最后生成两种下载产物各自的 SHA-256 manifest 项。DMG 根目录包含 `SafeClaude.app`、指向 `/Applications` 的快捷入口和安装说明。缺少 Apple 发行凭据时只能完成本地包验证，不能标记为正式发行。可用 `Scripts/package-dmg.py` 和 `Scripts/validate-dmg.py` 单独构建并验证本地评估镜像：

```sh
python3 Scripts/package-dmg.py /tmp/SafeClaude.app /tmp/SafeClaude.dmg \
  --volume-name SafeClaude
python3 Scripts/validate-dmg.py /tmp/SafeClaude.dmg \
  --version 0.1.0 --build-number 1
```

E08 自动网络校时状态读取随 `.app` 提供独立 LaunchDaemon。用户在“网络与隐私”设置中主动注册并批准后，helper 每 60 秒运行固定的 `systemsetup -getusingnetworktime` 并将 `On`、`Off`、采样时间写入 root 所有的状态文件；不保存命令原文，不修改系统时间设置。Agent 仅接受权限、所有者和时效校验通过的状态；关闭校时会扣分，服务未注册、采样失败或状态超过 180 秒时保持 unknown/hold。helper 同时提供固定 XPC 接口，只能暂停采样、删除经所有者/类型/权限/大小/硬链接检查通过的状态文件，或恢复采样，不接受命令或路径参数。LaunchDaemon 需要 app bundle 可由系统服务访问；正式部署位置为 `/Applications`。当前未签名包不能完成实际注册授权验收。

## 本地安装集成开发流程

仓库内安装夹具使用的安装器也支持可回滚的原地升级。升级前会核对安装清单、shell 与 Claude 设置、官方 wrapper 和 LaunchAgent；发现用户改动或活动受管会话时会拒绝替换。成功升级会保留现有 shell 与 Claude 配置：

```sh
python3 Scripts/setup-integration.py install
python3 Scripts/setup-integration.py upgrade
python3 Scripts/setup-integration.py uninstall
```

这是开发阶段的本机集成流程，会写入用户 shell 配置、Claude `settings.json` 和 LaunchAgent。安装时会保留并合并现有的 `StopFailure` hooks，只提取 Claude Code 提供的固定错误类别和 session 标识摘要；错误详情与消息文本不入库。触发 G03/G04 门槛后 Agent 会按已登记进程身份处置会话。卸载会校验并只移除 SafeClaude 插入的配置片段；如果设置内容被改动，卸载会停下并保留安装以避免破坏用户配置。使用 `--no-settings` 会跳过该 hook。正式签名公证发行与用户自助更新尚未完成，其他未实现检查仍按 unknown/hold 处理。

本地发行 `.app` 携带 universal2 安装器运行时、Python 运行时许可证、shim、process wrapper、LaunchDaemon plist 与集成脚本；安装/升级可直接使用发行 App 内已构建的组件，不需要源码仓库、系统 Python 或重新编译。隔离试装方式如下：

```sh
"/Applications/SafeClaude.app/Contents/Resources/Installer/safe-claude-setup" install
"/Applications/SafeClaude.app/Contents/Resources/Installer/safe-claude-setup" upgrade
"/Applications/SafeClaude.app/Contents/Resources/Installer/safe-claude-setup" uninstall
```

默认安装会把组件放在用户级 Application Support，合并 Claude `processWrapper` 与 `StopFailure` hook，并创建用户 LaunchAgent 和菜单栏启动项。首次启用窗口已接入菜单栏集成管理，可在窗口内选择 Claude 可执行文件和启动入口、查看配置变更并执行安装、升级或卸载。图形化集成与 App 内 CLI 使用随包安装器，不依赖系统 `/usr/bin/python3`；源码开发脚本仍可通过 `python3 Scripts/setup-integration.py` 调用。

首次启用窗口也提供图形化卸载。卸载先暂停新会话并确认受管会话已结束，再撤销 SafeClaude DNS System Extension 和特权校时 LaunchDaemon，之后安全移除 root 所有的校时状态快照，最后清理 shell、Claude 设置与用户级安装。校时 LaunchDaemon 通过只允许操作固定状态文件的本机 XPC 服务执行快照删除；文件类型、所有者、权限、大小和硬链接数不符合预期时会停止卸载并保留可恢复的安装组件。遇到系统要求重启、服务状态不明、活动会话或用户配置改动时同样会停止并保留安装组件。

“数据与诊断”中可主动开启桌面状态通知。首次开启时 macOS 会请求通知权限；持续的待确认/拦截状态只提示一次，恢复后再提示一次。通知只包含通用状态说明，不含出口 IP、代理设置、路径或会话内容。

同一设置页的“导出脱敏诊断”会打开系统保存面板，导出本次有效检查的版本、状态、分数和白名单规则摘要。JSON 不包含自由文本原因、来源、建议、IP、代理配置、启动票据或本地路径，导出文件权限设为仅当前用户读写。

## 当前验证

GitHub Actions 的 macOS 工作流位于 `.github/workflows/macos-ci.yml`，在 push、pull request 和手动触发时运行 Swift 测试、DNS System Extension 静态分析、plist/entitlements lint、隔离启动/网络/唤醒/安装/ENOSPC 夹具，并构建 universal2 未签名 App 与 DMG；工作流会上传保留 14 天的本地验证产物。签名、公证和 Gatekeeper 仍由具备发行凭据的发行环境执行。

```sh
swift test
python3 Tests/Fixtures/proxy_fixture.py
python3 Tests/Fixtures/geo_proxy_fixture.py
python3 Tests/Fixtures/exec_fixture.py
python3 Tests/Fixtures/claude_runtime_fixture.py
python3 Tests/Fixtures/claude_wrapper_rejection_fixture.py
python3 Tests/Fixtures/claude_proxy_runtime_fixture.py
python3 Tests/Fixtures/claude_tls_runtime_fixture.py
python3 Tests/Fixtures/agent_integration_fixture.py
python3 Tests/Fixtures/managed_generation_fixture.py
python3 Tests/Fixtures/managed_generation_fixture.py --network-change
python3 Tests/Fixtures/managed_generation_fixture.py --wake-notification
python3 Tests/Fixtures/trusted_endpoint_fixture.py
python3 Tests/Fixtures/managed_generation_fixture.py
python3 Tests/Fixtures/managed_generation_fixture.py --real-claude
python3 Tests/Fixtures/managed_generation_fixture.py --real-claude --network-change
python3 Tests/Fixtures/managed_generation_fixture.py --real-claude --wake-notification
python3 Tests/Fixtures/rosetta_integration_fixture.py --app /tmp/SafeClaude.app
python3 Tests/Fixtures/agent_storage_failure_fixture.py
python3 Tests/Fixtures/disk_pressure_fixture.py
python3 Tests/Fixtures/setup_integration_fixture.py
python3 Tests/Fixtures/launchd_agent_fixture.py
python3 Tests/Fixtures/packaged_setup_fixture.py /tmp/SafeClaude.app
python3 Tests/Fixtures/wrapper_agent_rejection_fixture.py
python3 Tests/Fixtures/wrapper_agent_rejection_fixture.py --real-claude
python3 Tests/Fixtures/preflight_latency_fixture.py --app /path/to/SafeClaude.app --samples 40
python3 Tests/Fixtures/cold_preflight_latency_fixture.py --app /path/to/SafeClaude.app --samples 40
```

`setup_integration_fixture.py` 在临时 HOME 中用隔离的 launchctl 服务模型注入升级 bootstrap 失败，验证新服务被卸载、旧安装与两个 LaunchAgent 均恢复；它不会操作当前登录用户的 launchd 域。

`launchd_agent_fixture.py` 在当前用户 GUI launchd 域注册唯一临时服务，将 `HOME`、PATH 和 IPC socket 指向私有临时目录，验证 Agent 启动及 SIGKILL 后自动重启；无论 bootstrap 是否完整成功，夹具都会尝试 bootout 该唯一服务。

`managed_generation_fixture.py --real-claude` 将真实 Claude Code、官方 `processWrapper` 启动路径和 Agent 的 F04 运行代次监视接在一起：保持 Claude 子进程在隔离 wrapper 门闸内，不发起模型请求；随后改变运行策略，验证受管 Claude 会话被中断且无关进程存活。加 `--network-change` 可由仅 Debug 的测试 IPC 推进 Agent 网络代次；加 `--wake-notification` 可发布 `NSWorkspace.didWakeNotification`，验证唤醒后的网络代次失效和会话复核。两个变体均验证同一会话处置链路，不改动系统网络或触发真实硬件睡眠；因此不代替真实路由变化及实际睡眠/唤醒验收。真实 Claude 变体依赖本机已安装 Claude Code。

`managed_generation_fixture.py --wake-notification` 通过仅 Debug 的 IPC 在隔离 Agent 内发布 `NSWorkspace.didWakeNotification`，验证受管会话在唤醒后触发 F04 并被中断、旁观进程保持运行；加 `--real-claude` 可经本机 Claude 官方 wrapper 验证同一路径，不发起模型请求。它验证通知处理和会话处置，不替代真实硬件睡眠/唤醒测试。

`rosetta_integration_fixture.py --app <universal2-app>` 使用 x86_64 切片启动包内 Agent 和 CLI，经独立 IPC 查询完整 64 项状态；可在 Apple silicon + Rosetta 或 Intel 主机运行。Apple silicon 上的 Rosetta 结果不替代 Intel 实机系统服务验收。

`agent_storage_failure_fixture.py` 分别损坏会话 journal 与 G02 启动频率状态文件，确认 Agent 进入 hold 或将 G02 保持 unknown，并在 Claude exec 前拒绝启动。

`disk_pressure_fixture.py` 创建并挂载 64 MiB 临时 HFS+ 磁盘映像，填至真实 `ENOSPC`，验证启动频率与受管会话 journal 写入都 fail closed，Agent 仍保持运行；夹具退出时卸载并删除映像，不写入用户卷。

`preflight_latency_fixture.py --app /path/to/SafeClaude.app --samples 40` 以指定发行包中的 Agent、SafeClaude launcher 和 `claude --version` 执行多次受控启动预检；夹具读取 bundle build number，并确认 Agent/CLI 不含 Debug fixture IPC 动作。使用合成 TLS 风险使 Claude 在模型请求前被阻断，不读取账号凭据或发起模型请求；若清理 Agent 需要从 SIGTERM 升级到 SIGKILL，夹具会失败。省略 `--app` 时使用 Debug 构建；可设置 10–1000 次样本。

`cold_preflight_latency_fixture.py --app /path/to/SafeClaude.app --samples 40` 每次启动全新的隔离 Agent，再通过该发行包中的 launcher 和 `claude --version` 执行同一阻断预检，用于测量发行构建的 Agent 冷进程启动路径；夹具会读取 bundle build number，并确认 Agent/CLI 不含 Debug fixture IPC 动作。使用合成 TLS 风险，不读取账号凭据或发起模型请求；若清理 Agent 需要从 SIGTERM 升级到 SIGKILL，夹具会失败。省略 `--app` 时使用 Debug 构建；可设置 10–100 次样本。

`benchmark-agent-runtime.py --agent /path/to/safe-claude-agent --duration 7200 --interval 2 --json-output /path/to/new-report.json` 可对隔离 Agent 做长时空闲资源测量。JSON 报告只在测量成功、Agent 通过 SIGTERM 正常退出后写入；输出路径必须尚不存在，报告文件权限为仅当前用户读写。

`agent_integration_fixture.py` 使用临时 HOME 和本地 Agent 验证受信/未受信 endpoint 在进程环境、inline `--settings` 和文件型 settings 中的 A09 评分与敏感 URL 脱敏；同时覆盖 Claude 的显式项目目录名、用户自定义 `autoMemoryDirectory` 和 inline `--settings` 记忆目录，确认只做本地 metadata census，记忆正文与目录路径不进入 Agent 响应或启动输出。`trusted_endpoint_fixture.py` 单独验证真实 launcher 的策略加载、endpoint 信号 IPC、票据复核和未受信启动阻断。

`managed_generation_fixture.py` 通过 Debug Agent 的受管会话监控循环注入确定性的完整规则评估：先确认 F04 通过，再在会话运行中原子更新运行门槛，验证 F04 代次变化、Agent 对受管进程发送 SIGINT，并确认无关进程仍运行。该夹具验证 Agent 的监控与处置链路，不替代真实网络信号采集验收。

`claude_proxy_runtime_fixture.py` 与 `claude_tls_runtime_fixture.py` 使用临时 Claude 配置、合成 API key 和 loopback API/代理，核对 Claude Code 的 HTTP、HTTPS CONNECT、NO_PROXY、大小写变量冲突以及用户/项目/local settings 选择的真实请求路径；不访问真实模型服务，不读取用户账号配置。

`swift run safe-claude probe-config <目标域名>` 只诊断代理配置，不启动或保护 Claude；当前能力与后续门禁见 [阶段 01 验证记录](docs/validation/phase-01/observations.md)。

已安装后可运行 `safe-claude doctor` 检查 Agent 连接、当前 PATH 是否选中本安装的 `claude` shim，以及 App 与 Agent 所需的模型生命周期资源是否完整。doctor 会从已安装的 CLI 位置识别安装前缀；报告只输出布尔状态，不包含本机安装路径。

Agent 监听 macOS 系统唤醒通知；电脑唤醒后会立即使受管会话的旧检查状态失效，并触发重新评估。隔离集成夹具会模拟该系统通知验证状态转为待复核；真实睡眠时长、唤醒后网络恢复和资源压力仍需在发行验收中实机测试。

`swift run safe-claude trace-check api.anthropic.com` 可在当前命令环境中做一次不带登录凭据的出口诊断，默认只输出是否取得 IP，不打印 IP 或代理密码。该命令尚未合并 Claude 设置文件与后台进程上下文。

`swift run safe-claude assess-current --ipwho` 会查询当前 API 出口并向 IPWho 发送该出口 IP，用于国家、时区和 ASN 检测；输出不包含 IP。查询按目标域名解析 HTTP(S) 环境代理和 NO_PROXY；系统代理、PAC 或无法识别的配置会暂停查询。该诊断只代表当前进程上下文，尚有规则未实现，决策会保持 `hold`。地区语言候选来自 [Unicode CLDR 48 数据与许可证](DataSources/CLDR/LICENSE)。

在应用设置中启用 IPWho 后，Agent 还会向 IPWho 查询登录和平台目标的出口 IP，用于比较不同目标的 ASN；相同 IP 的查询会合并并暂存。

同一授权也用于 D02/D03 递归 DNS 出口国家检查：标准 port 53 使用固定 Akamai TXT/UDP 查询，标准 port 853 使用系统 TLS 信任校验的 DoT/TCP 查询；当系统明确提供匹配的 DoH URL、服务器 IP 和 TLS 身份时，使用该 HTTPS endpoint 发送固定 TXT 查询。无法唯一匹配或需要客户端证书的 DoH 配置保持未知，不发送裸 UDP。resolver 出口 IP 只在内存中用于向 IPWho 查询国家；短期共享证据只保存国家码与解析器摘要，不写入原始出口 IP 或 DNS 响应。

“网络与隐私”设置可单独启用 C07 UDP/STUN 出口国家比较，并配置 `主机名:端口`。该选项默认关闭；启用后 STUN 服务会看到 UDP 探测的公网 IP，SafeClaude 会把映射地址发送至 IPWho 查询国家。需同时允许 IPWho；任一探测或地理结果缺失时按 unknown/hold 处理。映射 IP 不写入报告、历史或日志。

可在诊断命令后增加 `--proxycheck`，同时向 ProxyCheck 查询同一出口 IP 的信誉信息。两家查询并行执行；第三方会收到被查询的 IP。ProxyCheck v3 的 `operator.services=residential_proxies` 会触发 B07；其 `device_estimate.address` 达到 25 也会以高共享出口启发式触发 B07。25 是 SafeClaude 自定的保守阈值，供应商没有定义该阈值。B07 只在响应 `last_updated` 可解析且底层 IP 记录不超过 15 分钟时采用这些信号；查询时刻不会刷新底层记录时间。两种信号都不能证明当前 IP 是 P2P 节点；P2P 属性仍无可持续来源，所以 B07 继续保持待确认。可通过进程环境变量 `SAFE_CLAUDE_PROXYCHECK_API_KEY` 提供自己的 ProxyCheck API key；密钥不会出现在诊断输出或 curl 参数中。ProxyCheck 响应最多在内存缓存 15 分钟；密钥访问、供应商限流和签名发布仍需完整验证。

在“网络与隐私”中单独开启 ProxyCheck 查询后，SafeClaude 才会将本次 Claude API 出口公网 IP 发送至 ProxyCheck。可不提供 API key 使用无 key 额度；供应商当前文档列出按查询出口 IP 每日 100 次，无 key 查询仍会被计数并记录查询方 IP。已有 key 时由 Keychain 提供，额度按供应商账户规则执行。关闭授权时不会发送地址，对应 ProxyCheck 证据保持 unknown；其他已启用信誉来源仍独立参与评分。ProxyCheck v3 结果按 IP、key 与有效路由隔离后在内存缓存最多 15 分钟。

“数据与诊断”设置可保存 ipapi.is API key 来启用 B02 近期滥用与 B03 已知开放代理检测。只有与本次 `api.anthropic.com` trace IP 完全匹配、时间有效的供应商结果才会参与评分；结果按 key 和网络路由隔离后在内存缓存 6 小时。B02 还会读取 ProxyCheck v3 的 30 天攻击类别计数（请求参数 `risk=2&days=30`）；任一类别计数大于零即计入近期滥用风险，缺失或格式异常保持 unknown。两家来源冲突会触发 H03，并保留已观测到的风险。`is_proxy=false` 不足以排除住宅或移动代理，所以 B03 仍保持待确认。

D08 会检查启动环境、Claude 用户/项目/托管设置与本次 `--settings` 中的 `CLAUDE_CODE_CLIENT_CERT`。SafeClaude 只读取首个 PEM 公共证书块的有效期；不会读取后续私钥，路径和证书内容也不会进入 IPC 或检查报告。证书格式无法识别或文件无法安全读取时保持 unknown/hold；完成设置扫描且未配置客户端证书时标为不适用。
