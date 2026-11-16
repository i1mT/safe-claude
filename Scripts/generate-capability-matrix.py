#!/usr/bin/env python3
"""Generate an honest, reproducible snapshot of phase-01 rule capabilities."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs/design/check-catalog.md"
OUTPUT = ROOT / "docs/validation/phase-01/capability-matrix.md"

PARTIAL = {
    "A02": ("部分实现", "仅当 Claude 有效路由解析为 HTTP(S) 代理时，以 5 秒内成功的 api.anthropic.com HTTPS trace 证明 CONNECT/TLS 可用；路由冲突、失败或过期保持 critical unknown，直连不适用"),
    "A01": ("部分实现", "官方日期快照和部分国家分类已接入，政策过期及未适配属地保持 unknown"),
    "A03": ("部分实现", "真实 Claude Code 2.1.323 loopback 端到端夹具验证 HTTP/HTTPS CONNECT、NO_PROXY、大小写代理冲突及用户/项目/local settings 对请求路径的选择；SafeClaude 在线 trace 与真实用户代理、目标分流和 IPv6 路由等价仍待验收"),
    "A04": ("部分实现", "三个目标的环境级 trace 可发现国家差异；Claude 有效设置和目标覆盖尚需验证"),
    "A05": ("部分实现", "启用 IPWho 后比较各目标出口 ASN；严格绑定 IP、国家和观测时间，Claude 配置路径仍需验证"),
    "A06": ("部分实现", "直连路径下并行探测 IPv4 和 IPv6；两者均可达时计分，代理路径及失败原因保持未知"),
    "C08": ("部分实现", "以设备本地 Keychain 密钥生成稳定 HMAC 路由摘要，代理与活动 DNS resolver 每两秒采样；安全状态文件仅保存摘要和单调时钟时间戳，跨 Agent 重启恢复 10 分钟滚动计数。少于 3 次只有连续覆盖完整 10 分钟且最近采样不超过 5 秒才通过；缺样、超过 10 秒的间隔、唤醒或密钥轮换会重置覆盖窗口并保持 critical unknown；未观测到的采样间隔内变化仍无法还原"),
    "C06": ("部分实现", "启动检查与受管会话共享短期 HMAC 出口基线；进程网络等价及恢复后的连续基线尚待验证"),
    "C01": ("部分实现", "对比连续 24 小时历史窗口的首个确认国家与当前出口国家；首次安装及窗口不连续时不宣称基线成立"),
    "E10": ("部分实现", "受管会话对照启动时系统时区、区域和首选语言摘要；启动前和跨恢复状态仍需覆盖"),
    "E07": ("部分实现", "API HTTPS 响应 Date 与本机时钟对照，考虑请求耗时、精度、缓存年龄和时间跳变；其他时间源未覆盖"),
    "E08": ("部分实现", "用户授权注册 SMAppService LaunchDaemon；helper 以 root 只运行固定的 /usr/sbin/systemsetup -getusingnetworktime，每 60 秒读取一次并只持久化 On/Off/不可用类别与时间。Agent 只接受 root 所有、非组/其他可写、原子写入且 180 秒内的新鲜快照；On 通过，Off 扣分，缺失/失败/过期 critical unknown。未签名构建无法验证真实系统授权与 helper 注册"),
    "E09": ("部分实现", "检查受支持的 macOS 版本和 kern.hv_vmm_present；对 Claude 进程上下文严格验证 SSH_CONNECTION/SSH_CLIENT/SSH_TTY，仅传递命中布尔值。内核不可读保持 unknown；其他远端类型仍待验证"),
    "F05": ("部分实现", "顶层入口对照安装时选定的 Claude 路径和文件身份，变更时计分；签名完整性及其他安装待覆盖"),
    "F06": ("部分实现", "顶层启动环境中显式设置的 wrapper 与安装路径不一致时计分；全部设置作用域及实际生效待验证"),
    "F07": ("部分实现", "持续扫描并处置本用户与已选 Claude 可执行路径匹配、但不在会话记录中的进程；其他安装和入口覆盖待验证"),
    "F08": ("部分实现", "检测启动环境、用户/项目、CLI --settings、managed settings 文件与用户/设备偏好范围中的 CA 信任覆盖；只传递是否存在，不传输路径或内容；系统信任库差异与所有 Claude 版本仍需验证"),
    "F02": ("部分实现", "流式检测用户/项目、CLI --settings、macOS managed-settings 文件和四种用户/设备偏好范围中的 MDM 网络覆盖，不保留无关字段值；MDM 其他策略结构仍需验证"),
    "F03": ("部分实现", "解析用户/项目、CLI --settings、macOS managed settings 文件和四种用户/设备偏好范围中的 MDM 网络与 locale 字段；MDM 其他策略结构仍未知"),
    "F04": ("部分实现", "非会话上下文标为不适用；受管会话遇到网络代次或运行评分输入/门槛策略变化后重新评估并计入 F04；策略代次比较覆盖 IPWho、UDP/STUN、DNS 协议、受信 endpoint 与运行门槛；Debug Agent 端到端夹具覆盖运行改阈值、网络代次和 NSWorkspace 唤醒通知，并验证仅中断身份匹配的受管进程；真实硬件睡眠/唤醒、真实采集输入和长期窗口联合验收仍待验证"),
    "A07": ("部分实现", "NO_PROXY 域名/端口、IPv4/IPv6 字面量、CIDR 与括号 IPv6 端口匹配已实现并测试；域名目标遇到 CIDR 时因无目标解析地址证据保持 critical unknown，跨设置作用域仍待验证"),
    "A08": ("部分实现", "代理 URL 类型识别与 SOCKS 拒绝已测试；各 Claude 版本待实测"),
    "A10": ("部分实现", "本次 Agent 启动按过滤后的 Claude 环境并行检查 api.anthropic.com、claude.ai、platform.claude.com；三项都须在 5 秒内取得新鲜、IP 有效且主机绑定正确的 trace，任一缺失/过期/失败均计分并 hold；目标路径和代理行为仍需真实用户网络实测"),
    "A09": ("部分实现", "本机 HTTPS DNS origin 受信策略已贯通进程环境、用户/项目/managed settings、managed preferences 与 CLI --settings；host 按 DNS label 语法逐段校验，策略文件在读写两端共享 16 KiB 硬上限；真实 Agent 夹具覆盖环境变量、inline 和文件型 settings 的受信/未受信评分与脱敏；系统 MDM preferences 域的实机配置尚未演练"),
    "B01": ("部分实现", "仅在用户显式授权 ProxyCheck 查询后采集；匿名请求每日额度按查询出口 IP 计数。Tor 字段及 IP 绑定已接入，在线供应商行为待端到端验证"),
    "B02": ("部分实现", "ipapi.is 近期滥用字段与用户授权后采集的 ProxyCheck v3 30 天攻击类别计数共同计分；两者按当前 Claude API 出口 IP 和新鲜 trace 绑定，阳性冲突触发 H03，缺失/未授权来源保留 unknown；ProxyCheck 请求固定 risk=2&days=30，在线供应商响应尚未实测"),
    "B03": ("部分实现", "ipapi.is 已知开放代理阳性可计分并绑定当前 API 出口；negative/missing 不排除住宅或移动代理，保持 unknown；在线凭据/供应商响应尚未实测"),
    "B04": ("部分实现", "仅在用户显式授权后采集 ProxyCheck VPN/代理字段；未授权保持 unknown；路径等价与供应商行为待验证"),
    "B05": ("部分实现", "仅在用户显式授权后采集 ProxyCheck 机房字段；未授权保持 unknown；供应商行为待验证"),
    "B06": ("部分实现", "仅在用户显式授权后采集 ProxyCheck 匿名字段；未授权保持 unknown；供应商行为待验证"),
    "B07": ("部分实现", "ProxyCheck v3 operator.services 的 residential_proxies 标签和 device_estimate.address >= 25 启发式接入；只接受 last_updated 在 15 分钟内的源记录并绑定本次 API 出口 IP；风险阳性计分但因 P2P 属性仍无来源而保持 unknown/hold，低设备估算/空列表不能证明无 P2P；25 为 SafeClaude 自定阈值，不是供应商阈值"),
    "B08": ("部分实现", "ProxyCheck 综合风险已接入并去重；供应商行为待验证"),
    "C02": ("部分实现", "隔离历史检测国家变化并持久化摘要；完整观测窗口与基线未验收"),
    "C03": ("部分实现", "隔离历史检测 ASN 变化并持久化摘要；完整观测窗口与基线未验收"),
    "C04": ("部分实现", "检测出口变化，聚合 IPv6 /64 并持久化摘要；完整观测窗口未验收"),
    "C05": ("部分实现", "IPWho 经纬度与 Claude trace 国家交叉核对，距离只在本机计算，历史仅保存跳变标记；由于供应商未提供精度范围，阳性扣分但保持 critical unknown，阴性也不标为通过"),
    "D07": ("部分实现", "仅提取 Claude 进程及有效 settings 中 NODE_OPTIONS 的 --tls-min-v1.0/--tls-min-v1.1 布尔信号；未发送选项原文。其他原生/自定义传输策略、Node 显式 argv 覆盖及实际握手版本未验证，配置读取失败保持 critical unknown"),
    "C07": ("部分实现", "RFC 8489 Binding 探测、IPWho 国家核验、用户授权及端点配置已接入；真实出口等价、UDP 网络故障和延迟门禁待验证"),
    "D05": ("部分实现", "启动环境、用户/项目、CLI --settings、系统 managed settings 及四种用户/设备偏好范围中显式关闭 TLS 时扣分；MDM 其他策略结构待验证"),
    "D06": ("部分实现", "TLS 目标证书验证失败时按 curl 错误码计分；Claude 自定义信任配置等价未验证"),
    "D08": ("部分实现", "从启动环境、用户/项目/托管设置及内联 --settings 检查首个 PEM 公共证书有效期；只传递有效/临期/过期标签，不读后续私钥，路径异常或多证据冲突保持 critical unknown；其他证书格式未覆盖"),
    "G03": ("部分实现", "安装器将官方 StopFailure 错误类别 hook 合并进 Claude settings.hooks，保留已有 hook 并在卸载时仅移除 SafeClaude 插入片段；仅保存 hash 后的 session_id 与事件类别/时间，并将 digest 绑定到登记进程出生身份。滚动计数进入每轮受管会话复评；60 秒超过 10 次 API 失败 turn 后按 G03 权重更新评分，仅当扣分后低于 runtimeMinimumScore 才按核验身份异步结束会话，超窗后风险状态恢复。分数基线或策略缺失时 fail-closed。StopFailure 是 API 错误结束 turn 的计数代理，不是底层准确 retry 计数。Claude 版本、未使用 settings 安装和真实错误路径仍待验收"),
    "G04": ("部分实现", "从同一 StopFailure hook 中计 authentication_failed、oauth_org_not_allowed、account_on_hold、billing_error、cloud_credential_error 及保守回退的 server_error/unknown 类别；digest 绑定登记进程出生身份，10 分钟滚动计数进入每轮受管会话复评。达到 3 次后按 G04 权重更新评分，仅当扣分后低于 runtimeMinimumScore 才按核验身份异步结束会话，超窗后风险状态恢复；分数基线或策略缺失时 fail-closed。错误详情、消息文本和原 session_id 不落盘；cloud_credential_error 专用分类需要 Claude Code 2.1.267+，更早版本的凭据失败可能落在 server_error/unknown，按认证风险保守计入。hook 未安装或 Agent 事件存储失败时规则保持 unknown/hold"),
    "D01": ("部分实现", "macOS 15 DNS Proxy 捕获 Claude 目标域名 UDP/TCP flow；以 audit token 和进程出生身份绑定受管会话，将 resolver 摘要与当前 SystemConfiguration 生效 resolver 集合比较。不匹配扣 12 分；首次查询前、配置不可读时 critical unknown。只比较当前配置，不构成持久锁定"),
    "D02": ("部分实现", "用户启用 IPWho 地理查询后，对 port 53 resolver 使用固定 Akamai UDP TXT 查询，对标准 port 853 DoT 使用系统信任校验的 TLS/TCP；DoH 只在 Network Extension 能唯一取得系统 serverURL、服务器 IP/TLS 身份且与实际 flow endpoint 匹配、无客户端证书时使用 HTTPS DNS-message POST。DoT ServerName 可用时用于 TLS 身份验证，冲突或缺项按未知处理。国家不一致扣 6 分；出口 IP 仅在内存发送至 IPWho，spool 只含国家码和哈希身份。其他端口、无法匹配/过期/冲突 evidence critical unknown；DoH/DoT 在线证书与供应商行为尚未实测"),
    "D03": ("部分实现", "枚举当前 SystemConfiguration 活动 resolver；port 53 使用 UDP、标准 port 853 使用系统信任校验的 DoT/TCP；DoH 仅在 Network Extension 唯一取得系统 HTTPS URL、服务器 IP/TLS 身份且与 flow endpoint 匹配、无客户端证书时探测并按 resolver digest 绑定 country-only spool 证据。多个 resolver 国家不一致扣 4 分。其他端口或任一 endpoint/TLS/route 歧义保持 critical unknown，不误发裸 UDP。单个 resolver 不适用；任一必要 resolver 未核验仍 unknown。真实 DoH/DoT 在线行为尚未验收"),
    "D04": ("部分实现", "DNS Proxy provider 按目标域名读取当前 systemDNSSettings 中适用的 DoH/DoT/明文协议并放入身份绑定短期证据；用户可持久选择 DoH 或 DoT 任一、仅 DoH、仅 DoT，明文或指定协议不匹配扣 8；旧版未区分协议的证据只满足任一加密协议策略。会话降级基线写入 0600 SessionJournal 并在 Agent 重启后恢复。首次观测、路由歧义和实机协议路由仍待验证"),
    "E01": ("部分实现", "IPWho 时区按本次 api.anthropic.com 出口 IP 绑定，并与 macOS 系统时区比较；目标出口依调用方传入的 Claude 启动代理环境采样。信誉授权、在线响应和国家冲突仍需实测"),
    "E02": ("部分实现", "比较系统时区、进程 TZ、用户/项目、CLI --settings、托管文件和四种用户/设备偏好范围的 TZ；其他配置和 runtime 继承待验证"),
    "E03": ("部分实现", "IPWho 国家按本次 api.anthropic.com 出口 IP 绑定，再与 CLDR 48 国家语言候选及 macOS 首选语言比较；在线信誉/国家响应仍需实测"),
    "E04": ("部分实现", "使用本次 Claude 启动上下文中的 TZ/LANG/LC 值，并合并用户/项目、CLI --settings、托管文件和四种用户/设备偏好范围比较系统配置；Node/runtime 对 locale 的最终映射仍待对照"),
    "E05": ("部分实现", "检查启动环境、用户/项目、CLI --settings、托管文件和四种用户/设备偏好范围中 LANG/LC 覆盖冲突；其他策略结构待验证"),
    "E06": ("部分实现", "IPWho 国家按本次 api.anthropic.com 出口 IP 绑定，并与 macOS 区域格式比较；在线信誉/国家响应和区域别名边界仍需实测"),
    "F01": ("部分实现", "对 http_proxy/HTTP_PROXY、https_proxy/HTTPS_PROXY、all_proxy/ALL_PROXY、no_proxy/NO_PROXY 四组大小写变量检查冲突并扣分；仅保留变量名，不同值的代理 URL 与凭据不进入快照。跨设置作用域的批准基线仍未接入"),
    "G01": ("部分实现", "统计 Agent 当前登记的受管会话：超过 4 个扣标准分，超过 8 个提高扣分；不完整会话身份仍由启动阻断处理"),
    "G02": ("部分实现", "统计已授权顶层启动的 60 秒滚动窗口：10 次以上扣标准分、30 次以上提高扣分；仅持久化时间戳并跨 Agent 重启恢复，其他入口由 F07 单独监测"),
    "G05": ("部分实现", "完整进程快照中发现不同路径 Claude 安装时扣分；完整扫描无第二安装时通过，进程身份读取不完整时保持 unknown；其他客户端形态未覆盖"),
    "G06": ("部分实现", "启动 --model、Anthropic 模型环境变量、settings model 和官方 model alias 映射参与生命周期判断；deprecated/retired 扣 2，未识别、来源冲突、缺少显式模型或超过 45 天的清单保持 critical unknown；会话内 /model 切换及 provider deployment 不覆盖"),
    "G07": ("部分实现", "识别进程/设置开关；默认短路径支持安全的 CLAUDE_CODE_PROJECT_DIR_NAME 覆盖，唯一用户/托管设置与显式 --settings 自定义 autoMemoryDirectory 只做本地 .md 元数据盘点；项目来源、设置冲突、长路径 hash、worktree 映射或不安全目录保持 critical unknown"),
    "G08": ("部分实现", "受控启动中追踪 OAuth/API key/auth token/Bedrock/Vertex/key helper 类别，三次切换扣 8 并以 0600 元数据文件跨重启保留 10 分钟窗口；无法读取账号身份及未经过 shim 的启动不覆盖"),
    "H01": ("部分实现", "评分器按缺失来源扣分并 hold；原因归并仍需全量数据源验证"),
    "H02": ("部分实现", "评分器按辅助来源扣分并 hold；供应商授权和缓存仍需验证"),
    "H03": ("部分实现", "信誉和国家来源冲突可触发 hold；全部来源冲突尚未覆盖"),
    "H04": ("部分实现", "历史不足时扣分；跨重启摘要已实现，稳定基线条件尚未完成"),
}

NEXT = {
    "A": "实现当前进程代理配置、目的域名探测和经过授权的出口数据适配",
    "B": "选择授权信誉来源，验证数据许可、响应语义和过期行为",
    "C": "实现按 context 和网络代次隔离的观测历史与变更检测",
    "D": "验证 D02/D03 在线响应与 D04 实机协议路由；覆盖 Network Extension 授权、DNS Proxy 生命周期和故障恢复",
    "E": "实现本机实际环境采集，并取得版本化地区时区/语言映射",
    "F": "实现 Claude 配置解析、入口身份与防护覆盖验证",
    "G": "实现受管会话状态与安全的 Claude 错误/重试元数据适配",
    "H": "实现缺失/过期/冲突状态机并按策略 fail-closed",
}


def main():
    rows = []
    for line in CATALOG.read_text().splitlines():
        match = re.match(r"^\| ([A-H]\d{2}) \| ([^|]+) \|", line)
        if not match:
            continue
        rule, name = match.groups()
        status, next_action = PARTIAL.get(rule, ("未实现", NEXT[rule[0]]))
        rows.append((rule, name.strip(), status, next_action))
    assert len(rows) == 64 and len({r[0] for r in rows}) == 64
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 阶段 01：64 项采集能力矩阵",
        "",
        "2026-11-14。由 `python3 Scripts/generate-capability-matrix.py` 生成。",
        "“本地夹具/比较函数”不代表生产采集或端到端防护完成；未实现项目继续保持未知。",
        "",
        "| ID | 检查项 | 当前状态 | 下一步 |",
        "|---|---|---|---|",
    ]
    lines.extend(f"| {rule} | {name} | {status} | {next_action} |" for rule, name, status, next_action in rows)
    OUTPUT.write_text("\n".join(lines) + "\n")
    print(f"Wrote {OUTPUT.relative_to(ROOT)} with {len(rows)} rules")


if __name__ == "__main__":
    main()
