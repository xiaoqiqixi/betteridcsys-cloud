# 星屿云 云主控 / KVM 被控 0.2 设计

> 作者：架构设计（Claude）。实现：Codex。对标：魔方云（KVM 加强版）面向全球 VPS 商家的首个可用版本（功能成熟后才进入 1.0）。
> 现状基础：普通网络实例（Linux bridge）的创建/电源/删除、停止态快照与冷迁移、OVS VPC/NAT/浮动 IP、管理台 RBAC、`aster.controller/1` 开通。所有既有原则保持：先写意图再执行、uncertain 不自动重试、核对只读、不在不确定时删除客户盘、只允许白名单二进制。

## 1. 范围（0.2）

| 模块 | 0.2 交付 | 以后 |
| --- | --- | --- |
| 实例生命周期 | 重装（选镜像，密码或 SSH 公钥）、重置 root 密码、救援模式、Web 控制台（VNC）、暂停/解除暂停（计费驱动）、终止、升降配（离线 resize：CPU/内存/系统盘只增不减） | ISO 挂载、克隆、模板、回收站 |
| 镜像 | 主控镜像目录（批准哈希）、`GET /v1/images` 供财务同步、节点按需拉取（固定 HTTPS 源 + SHA256 校验） | 自定义上传 |
| 网络 QoS | 每实例进/出带宽限速（libvirt `<bandwidth>`，单位 Mbps）、流量统计（方向 in/out/both，按月重置日）、超额策略（限速到 X Mbps 或暂停） | 智能带宽、IPv6 普通网络 |
| 调度 | 自动派发守护进程（billing jobs 与 console operations，配置开关，默认关）、节点心跳（CL-2 安装 timer）、放置策略（最少实例 / 最多空闲内存 / 填满优先）、节点禁用新分配 | HA、热迁移 |
| 快照 | 保持“停止态、普通网络”约束，但对外暴露为服务能力；配额 N | 运行中一致性快照、定时/异地 |
| 财务接口 | **`aster.service/1`**（§3） | Webhook 回推 |

明确不做：实例内代理（guest agent）；控制台公开 VNC 端口；任意 URL/命令/XML 输入。

## 2. 节点实现要点

- **重装**：停机（观测 shut off）→ 校验目标镜像哈希 → 新建 overlay（原盘先改名保留，直到新盘首次启动被观测为 running 后才删除；失败则回滚到原盘）→ 新 cloud-init seed（新 instance-id，密码哈希或 SSH 公钥）→ 启动。
- **重置密码**：离线方式。停机 → 用 `virt-customize --root-password`（libguestfs，加入二进制白名单并在 doctor 检查）修改 → 启动。Windows 返回 `UNSUPPORTED_GUEST`。不使用 guest agent。
- **救援**：停机 → 以批准的救援镜像启动，原系统盘以第二块盘只读/读写挂载（配置）→ 退出救援时恢复原定义并启动。救援状态持久记录在节点 journal，进程重启后可恢复。
- **控制台**：domain XML 启用 `<graphics type='vnc' listen='127.0.0.1' autoport='yes'>`（不对外开放）；主控签发 60 秒一次性票据，浏览器 → 主控 `wss://<controller>/console/ws?ticket=` → 主控经 mTLS 隧道到节点 → 节点本地 VNC。主控提供 noVNC 页面 `/console/#ticket`（静态资源随主控前端打包，CSP 仅 self）。票据绑定 instance、owner、过期时间、单次使用。
- **暂停**：billing suspend = 强制停机 + 节点拒绝 start（`suspended` 标志持久化）；unsuspend 清除标志（不自动开机，除非请求 `start_after=true`）。
- **带宽/流量**：`<bandwidth><inbound average=.../><outbound average=.../></bandwidth>`（kbit→KB/s 换算写清楚并测试）；流量用 `domifstat` 增量计数持久化到节点 journal（处理计数器回绕和 domain 重启归零），主控汇总到 `controller_traffic`（instance, period, rx, tx）。
- **Resize**：离线；CPU/内存修改 domain 定义；系统盘 `qemu-img resize` 只增；需要客户机内扩分区由 cloud-init growpart 在下次启动完成。

所有新动作：节点 journal schema 递增；`Accept` 阶段的隔离/恢复遵循 CL-1 修复后的规则（拒绝必须恢复原记录）；新增 fake-runner 测试 + CI 原生 libvirt(TCG) 用例至少覆盖重装、救援、控制台握手、限速 XML。

## 3. `aster.service/1`（财务 ↔ 主控）

传输与 `aster.controller/1` 相同：HTTPS、Bearer（财务专用 billing token）、拒绝带 `Origin` 的请求、固定 DNS/CIDR、无重定向。资源以 `resource_id` 标识，每个请求带 `X-Aster-Owner-Ref`，与开通时的 `owner_ref` 不一致 → 404（不泄露存在性）。

| 方法 路径 | 说明 |
| --- | --- |
| `GET /v1/images` | 批准镜像目录 `[{id, family, name, version, min_disk_gb, sha256}]` |
| `GET /v1/services/{resource_id}` | `{protocol:"aster.service/1", resource_id, owner_ref, power(running/stopped/starting/stopping/rebooting/reinstalling/unknown), suspended, rescue_active, ipv4[], ipv6[], os_image_id, specs{cpu_cores,memory_mb,disk_gb,bandwidth_mbps}, traffic{rx_bytes,tx_bytes,limit_bytes|null,period_start,period_end}, capabilities{power,reinstall,reset_password,console,rescue,snapshots,metrics,upgrade}}` |
| `POST /v1/services/{resource_id}/actions` | 头 `Idempotency-Key = operation_id`、`X-Aster-Request-SHA256`；体 `{protocol, operation_id, owner_ref, action, params}`；action ∈ start/stop/reboot/force_off/reinstall/reset_password/rescue_enter/rescue_exit/snapshot_create/snapshot_restore/snapshot_delete/suspend/unsuspend/terminate/resize。响应 202 `{operation_id, status: accepted\|rejected, code}`；重放 409 返回首次结果。`params` 中密码字段只在内存中使用，不入库、不进审计。 |
| `GET /v1/services/{resource_id}/actions/{operation_id}` | `{operation_id, action, status: accepted\|running\|succeeded\|failed\|uncertain, code, finished_at}`（只读） |
| `POST /v1/services/{resource_id}/console` | `{url, expires_at}` 一次性票据 |
| `GET /v1/services/{resource_id}/metrics?range=1h\|24h\|7d\|30d` | `{step_seconds, points:[{at,cpu_percent,net_in_bps,net_out_bps,disk_read_bps,disk_write_bps}]}`（缺值 null） |
| `GET /v1/services/{resource_id}/snapshots` | `{items:[{id,name,status,size_bytes,created_at}], limit, requires_stopped}` |

协议 Go 类型放在 `contracts/billing`（与财务共享同一份 SDK，财务后端 vendor）。

## 4. 分工（并行 Codex 任务）

| 任务 | 范围 |
| --- | --- |
| **CL-3 Guest lifecycle + aster.service/1** | §2 重装/重置密码/救援/控制台(含 noVNC 页面与 wss 代理)/暂停/终止/resize；§3 全部接口与 `contracts/billing` SDK；镜像目录与 `/v1/images` |
| **CL-4 Automation + network QoS** | 自动派发守护进程（systemd unit，配置开关）、放置策略、节点禁用、带宽限速、流量统计与超额策略、`/v1/services/{id}` 中的 traffic 字段数据来源、监控数据保留（主控按 5 分钟聚合保存 30 天） |

两个任务都基于 `fix/node-state-machine`（CL-1）分支；`engine.go` 等公共文件冲突由后合并者解决。
