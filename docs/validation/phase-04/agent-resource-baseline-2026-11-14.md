# GuardAgent 空闲资源基线

日期：2026-11-14  
主机：macOS 15.6，Apple silicon  
运行对象：build 35 `/tmp/SafeClaude-design-20261114-build35.app` 中的 universal2 `safe-claude-agent`（Agent 运行时代码与 build 36 一致）  
测量方式：临时 HOME、独立 IPC socket、无 Claude 会话；每 2 秒采样进程累计 CPU 时间差和 RSS。

复现命令：

```sh
python3 Scripts/benchmark-agent-runtime.py \
  --agent /tmp/SafeClaude-design-20261114-build35.app/Contents/MacOS/safe-claude-agent \
  --duration 900 --interval 2
```

样本结果：

| 时长 | 区间样本 | CPU 均值 | CPU p95 | RSS 均值 | RSS 峰值 |
|---:|---:|---:|---:|---:|---:|
| 60 秒 | 29 | 0.171% | 0.991% | 15.27 MiB | 15.33 MiB |
| 300 秒 | 148 | 0.158% | 0.498% | 15.14 MiB | 15.22 MiB |
| 900 秒 | 446 | 0.146% | 0.498% | 15.66 MiB | 16.14 MiB |

三次运行期间 Agent 均保持存活并正常响应 SIGTERM。15 分钟样本结束时 Agent 以 SIGTERM 正常退出。测量没有启动 Claude 或发送模型请求。Agent 仍会执行正常后台环境探测，因此该结果代表空闲会话状态下的 Agent 负载，不是网络探测完全关闭的纯待机下限。

这是单机 Apple silicon、隔离 HOME 和无 Claude 会话的空闲基线；15 分钟采样用于发现明显的常驻资源问题，不替代跨多小时/睡眠唤醒周期、繁忙网络、Intel 主机或生产签名版本的资源验收。RSS 从 5 分钟均值约 15.14 MiB 到 15 分钟均值约 15.66 MiB，单次样本不足以判断长期内存增长趋势。

基准脚本当前接受 30–14400 秒，便于复测多小时空闲运行。build 51 的 7200 秒旧版观测结果及关闭状态字段限制见下文。

## 一小时复测

日期：2026-11-14  
运行对象：build 41 `/tmp/SafeClaude-design-20261114-build41.app` 的 universal2 Agent  
测量方式：临时 HOME、独立 IPC socket、无 Claude 会话；每 2 秒采样，共运行 3600 秒。

| 时长 | 样本数 | CPU 均值 | CPU p95 | RSS 均值 | RSS 峰值 |
|---:|---:|---:|---:|---:|---:|
| 3600 秒 | 1787 | 0.125% | 0.497% | 16.67 MiB | 17.78 MiB |

Agent 全程存活，运行结束后由基准脚本正常清理；没有 Claude 会话或模型请求。该一小时数据补充了短时空闲基线，仍属于单机、无会话的常驻负载样本，不覆盖睡眠唤醒、繁忙网络、Intel 或正式签名发行环境。

## 两小时旧版观测（结束状态字段缺失）

日期：2026-11-14  
运行对象：build 51 `/tmp/SafeClaude-coldstart-20261114-build51.app` 的 universal2 Agent  
测量方式：临时 HOME、独立 IPC socket、无 Claude 会话；每 2 秒采样，7200 秒。

| 时长 | 区间样本 | CPU 均值 | CPU p95 | RSS 均值 | RSS 峰值 |
|---:|---:|---:|---:|---:|---:|
| 7200 秒 | 3574 | 0.144% | 0.497% | 16.70 MiB | 18.08 MiB |

基准进程正常返回统计并退出，临时 HOME/socket 目录已清理；没有 Claude 会话或模型请求。但该次运行启动于基准脚本新增 `shutdown_escalated` 检查之前，输出没有记录 Agent 是否通过 SIGTERM 结束，还是升级为 SIGKILL。因此保留其 CPU/RSS 观测，不把它登记为满足新版关闭校验的完整性能门禁。其 Agent 代码早于 build 58，不能代表当前 Agent。代表 build 58 二进制的 build 56 两小时样本仍在运行。
