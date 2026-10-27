# Overlay 与受限网关执行器

本目录实现的是 `aster.overlay/1` **固定 VXLAN 对端 + 完整成员快照 + 经批准网关 appliance 接入**，可选增加[固定 namespace NAT](NAT.md)：经 root 批准的 IPv4 SNAT / TCP、UDP DNAT 与三阶段恢复联动；不提供 DHCP、动态路由协议或公网自动开通。原 `aster.node/2` 绑定、财务金额、支付与历史快照没有换义。真实双 KVM 节点流量、故障切换与回包验收仍需专门环境。

## 独立 root 审批

`OverlayConfig` 单独保存为 root 所有、0600、无符号链接文件；`Base` 必须与原 fabric 的 node / bridge / state directory 完全相同。一个桥仍只有一把 `fabric.lock`，不能用另一份 profile 绕过状态。

- `local_ipv4`、`peers` 是固定 IPv4，不接受域名、URL、`remote_ip=flow` 或任意设备名。每个参与节点一条固定 VXLAN tunnel，端口 4789，`key=flow`。
- `underlay_trusted_ack` 与 `trust_reference` 是运营方对独立隔离或已认证 underlay 的审批，不是 VXLAN 的密码学认证。没有自动 WireGuard / IPsec 配置。
- `underlay_mtu` / `guest_mtu` 至少相差 50 字节。执行时枚举本机真实接口，确认 LocalIPv4 唯一属于 UP、非 loopback、非租户桥接口且实际 MTU 足够；所有本地 VM 与 gateway TAP 的实际 MTU 必须等于 guest MTU。客户机自身 MTU 与已有 VM 路由须另验。
- `protected_cidrs` 必须明确列出管理与受保护网络。网关 allow prefixes 不能覆盖这些范围、任何 VPC、underlay 地址、0/8、loopback、link-local/metadata、multicast 或保留高位空间；`0.0.0.0/0` 不会被当作快捷授权。
- `gateways` 是精确批准的 router appliance TAP：固定 VM UUID、Interface ID、owner、VPC、MAC/IP 与 prefixes。不是宿主物理上联或管理网卡。`guest_networks` 关联不可变本地 VPC/owner/CIDR 与同一批准网关，供新 VM seed 生成明确路由；不伪造已有 guest 已更新。

配置更新导致新的 profile SHA。已经准备的同 epoch 任务必须继续匹配原完整快照与当前 root pin；运营方应先完成或显式恢复该 epoch，再批准新配置。

## 统一执行与三阶段屏障

`PrepareOverlay`、`ProgramOverlay`、`ReleaseOverlay` 接收完整 `overlayproto.Task`。任务 ID、阶段、全量快照、前序 SHA、root pins、恢复 heads 均进入请求 SHA；原始请求与 receipt 保留在 root-private 独立操作文件中。

1. **Prepare**：同 flock 持久意图 → 验证专用桥所有权 → 整桥 DROP 并读回 → root 回调暂停/隔离已有 VM → 创建缺失的固定 tunnel → 验证全部 OVSDB Interface / Port 身份 → 保持 DROP。主控须收齐所有节点 prepare receipt。
2. **Program**：仍验证整桥 DROP 和原身份映射 → 检查 meter 所有权 → 编程 drop meters 与 OpenFlow14 bundle → 精确 diff-flows / meter / UUID 读回。此阶段不调用 VM release。主控须收齐全部 program receipt。
3. **Release**：重新读回原计划和端口身份 → root callback 放行 VM → 再次读回 → 持久完成。单边失败不等于集群成功。

每个阶段同 ID/同 SHA 重放只返回历史 receipt，不重新执行 callback 或 host command；同 ID/不同 SHA 冲突。GET lookup 只是历史结果，不证明当前连通。`CheckOverlay` / `OverlayCheck` 是共享锁下只读检查，后者还必须验证目标的完整 frozen binding SHA、Enabled 与实际 TAP。

新 VM 可以在完整快照中保留 `Reserved` 身份，租约/IP/MAC/interface/network SHA 仍必须由主控冻结。缺席的本地 TAP 不生成 allow 流。正常 `OverlayActivate` 在同把锁内隔离、启动 paused、验证真正 TAP 后重编程、放行；`OverlayDeactivate` 必须确认 TAP 消失再重建其余成员规则。两者仅使用已经 release 的全局快照，不能临时新增授权成员。停止实例不会改写原快照或释放 IP。

## 数据面隔离与网关路由

- 默认 DROP；不使用 NORMAL、FLOOD、LOCAL、动态学习或未知单播泛洪；IPv6、VLAN/QinQ 和未知端口默认不通过。
- 本地源只接受精确源 MAC/IP 或 ARP sender；远端入口还须同时匹配固定 tunnel ofport、tun_src、tun_dst、VNI 和该 peer 所属成员。
- metadata 的 remote-ingress bit 阻止 peer→peer transit；目的仅为同 VPC 精确 MAC/IP，ARP 按单目标定向。
- 每个实际本地 VM 分别执行出站与入站 drop meter。它是 policer，不是排队整形，也不构成财务流量计费。
- 发往 gateway 的 IP 必须命中其允许 prefix 与固定目的 MAC；gateway 返回流量只接受批准源 prefix/网关地址，再按精确成员目的转发。跨节点 gateway 的回包仍不能成为 tunnel transit。
- 原 appliance 网关仍由外部系统提供 forwarding/return route。选择 root namespace NAT profile 后，本项目管理该专用 namespace 内的 nftables/forwarding/conntrack，固定 veth 路由与外部连接须由 root 预建并验证；详情见 [NAT.md](NAT.md)。不修改宿主默认路由、全局 forwarding、host nftables 或管理物理网卡。

OVSDB 读回包括 Interface UUID/type/options/external_ids/实际 ofport，以及 Port 单一 Interface、空 tag/trunks/vlan_mode；ofport 是观察结果而非授权身份。tunnel csum/df 与固定端点精确核对，端口复用或外部改动会阻断。全局 Interface 读回还拒绝其它桥的重叠 VXLAN ingress tuple（包括 wildcard / flow 与默认 UDP 端口）；不同 cluster 不能只靠独立 VNI 复用同一未区分的隧道入口。

## 故障恢复、保留与上限

- 任意已知专用桥的命令、callback、读回或持久化失败都会尝试有界 DROP 隔离并保留 uncertain；不自动重复 POST、callback 或“回滚成功”。隔离自身失败也明确 uncertain。
- 显式 recovery epoch 保存每个节点实际 `Head`，包含未收到失败 epoch 的落后/空节点；必须与节点当前 head 精确匹配。全部节点重新 prepare/fence，再过两道集群屏障，旧未知 receipt 不覆盖。
- 节点层额外冻结完整本地库存、所有待确认生命周期及期望电源状态，三阶段逐次 CAS；已存在且严格证明归属的 paused/running create/start、实际已 off 的 shutdown/force_off 才可显式收敛，不重跑原动作。delete/reboot、未知磁盘/迁移不通过此合同猜测完成。节点保存私有意图/结果证据，并在同一 schema 4 journal 事务写入原操作结果和独立 recovery completion；即使 fabric release 已成功，节点事务未确认时 POST/GET 仍返回 uncertain。无待确认 VM 的 OVS 漂移恢复同样需要 completion，不以旧成功记录冒充本次成功。
- fabric schema 3 的 durable overlay mode 墓碑阻止删 `overlay.owner` 后退回单机执行器。丢失/损坏当前状态不是空节点，必须停止并从可信证据恢复，不能重新申请 epoch 1。
- 每个 epoch / 操作分别持久为有界 root-private 文件，而非一个 64 项数组。超过 64 次正常变更仍可继续，历史精确 replay 保留。磁盘耗尽返回 uncertain，不删未知记录或静默裁剪历史；备份必须包含整个 fabric state directory。

## 依据与验收边界

- [OVS VXLAN](https://docs.openvswitch.org/en/latest/faq/vxlan/)：固定对端与控制面预置地址映射。
- [OVSDB Interface options](https://www.openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.txt)：端点、key、MTU 与接口字段。
- [OVS actions](https://www.openvswitch.org/support/dist-docs/ovs-actions.7.txt)：set_tunnel 与指令语义。
- [RFC 7348 §7](https://www.rfc-editor.org/rfc/rfc7348.html#section-7)：VXLAN 与外部封装注入风险。

代码测试覆盖真实编译规则的逐包策略决策（跨 VPC、错误源/VNI/peer、ARP 网关冒用、peer transit、保护路由与禁用成员）、三阶段屏障、exact replay/conflict、每条阶段命令故障、存储失败、未知 peer/MTU/VLAN/MAC、gateway 保护前缀、无 transit、70 epochs / 210 原始操作、local start/stop、完整 binding SHA、落后 head 恢复与 mode 墓碑。真实跨节点转发、丢包、MTU、限速和宿主重启不能以 fake runner 或规则解析测试替代。
