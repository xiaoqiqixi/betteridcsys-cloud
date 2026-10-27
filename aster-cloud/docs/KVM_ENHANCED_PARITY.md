# KVM 加强版功能对照与开发验收规格

本项目按用户指定的魔方云 **KVM 加强版功能范围**补齐独立主控及 KVM 被控，不把现有 Linux Bridge 基础链称为“加强版已完成”。本文记录当前差距、可交付顺序和逐项证据门槛，不是已完成的 Release 清单。当前主控数据库为 schema **12**；历史增量段落中的版本号仅表示各次模型引入版本。

## 1. 对标范围与不变边界

- 对标**能力和管理流程**，自主设计数据模型、协议、执行器和 UI；不接对方 API，不搬运源码、商标、图片、安装包或 CentOS 安装脚本。
- 保留 Go + Vue/TypeScript + MySQL、原生 systemd/TLS 部署；当前被控支持目标为 x86_64 Ubuntu 22.04/24.04。26.04 暂不支持，后续版本另行评审；22/24 分别验收；“能编译”不等于所有发行版兼容。
- 主控负责权限、租户资源、IPAM、调度、意图/审计；被控负责经审批的 libvirt/QEMU/KVM 与网络资源。财务负责销售和账务，不把付款成功当作虚拟机运行成功。
- 保持既有 `aster.controller/1`、`aster.resource/1` 和产品快照兼容。**金额、币种、支付幂等及历史快照不改**；本轮监控数据不自动入账，不添加按量扣费。普通 IPAM 管理对象仍只表示计划/预留；本轮新增显式 VPC 的同事务任务绑定与 `aster.node/2` 启停门禁。旧 `normal` 开通链不自动获得 VPC 能力，跨节点与受控路由/NAT 另经明确 `aster.overlay/1` 审批和 epoch，不能由旧 profile 自动获得，也不代表完整 VPC 产品已验收。
- 所有后续写动作继承稳定操作 ID、冻结参数和目标、写前持久化、重复请求校验、未知结果保留。丢响应后只核对原任务，不自动重发写入。
- 代码只更新 `main`。真实 KVM 验收已由用户延期，但没有豁免代码测试、MySQL 测试、危险操作保护或后续实机验收。
- 当前财务宿主机不是网络实验机。不得自动桥接其 SSH/公网网卡、清空防火墙、安装 OVS 后重接管理链路、运行 `curl | bash` 或关闭 AppArmor/TLS 校验。

## 2. 实际阅读的官方资料与判断边界

以下为本轮 2026-10-23 查阅结果，均为官方资料。仅短摘要，产品具体行为仍以原文和后续版本核对为准。

| 编号 | 官方资料 | 本轮读取程度及用于本项目的要点 |
| --- | --- | --- |
| R1 | [KVM 加强版和轻量版的区别](https://docs.idcsmart.com/docs/魔方云/1.%20环境部署/KVM加强版和轻量版的区别) | 正文已读取。主要区别在网络：加强版按 IP 限速、跨节点内网、VPC/浮动 IP 等；不能把基础 libvirt 网桥当作功能等价。 |
| R2 | [魔方云概览](https://docs.idcsmart.com/docs/魔方云) | 官方搜索返回功能表；作为监控、磁盘、租户、自助管理等功能域索引，非实现细节依据。 |
| R3 | [创建及管理实例](https://docs.idcsmart.com/docs/魔方云/3.%20管理实例/创建及管理实例) | 正文已读取。实例与客户、预备镜像、网络相关联；经典网络与 VPC 要区分。 |
| R4 | [添加 IP](https://docs.idcsmart.com/docs/魔方云/7.%20网络与安全/添加IP) | 正文已读取。地址池包含网关、前缀、DNS、可用节点及 VLAN/MAC 等管理属性。 |
| R5 | [弹性 IP](https://docs.idcsmart.com/docs/魔方云/7.%20网络与安全/弹性IP) | 正文已读取。公网地址是独立、归属客户且可绑定的资源，不是实例字符串字段。 |
| R6 | [NAT 转发与建站](https://docs.idcsmart.com/docs/魔方云/7.%20网络与安全/NAT转发与建站（单IP与NAT分开）) | 正文已读取。区分宿主单 IP 与独立转发方式；本项目不沿用其中不可回滚的宿主改造或默认放行大端口范围。 |
| R7 | [创建负载均衡](https://docs.idcsmart.com/docs/魔方云/7.%20网络与安全/负载均衡/创建负载均衡) | 正文已读取。独立资源、所属 VPC、监听器、后端及健康检查应分层管理。 |
| R8 | [实例配置调整](https://docs.idcsmart.com/docs/魔方云/3.%20管理实例/实例配置调整) | 正文已读取。变配需要明确停机影响；本项目不因参考系统会强制停机就隐式强停客户实例。 |
| R9 | [流量计费设置](https://docs.idcsmart.com/docs/魔方云/3.%20管理实例/流量计费设置) | 正文已读取。额度、方向、重置日分开；本项目计量账本与金额账本保持分离。 |
| R10 | [更换网络类型](https://docs.idcsmart.com/docs/魔方云/3.%20管理实例/更换网络类型) | 官方搜索正文可读。跨 VPC、经典/VPC 切换是有状态资源变更，不是改显示标签。 |
| R11 | [添加本地存储](https://docs.idcsmart.com/docs/魔方云/4.%20磁盘与存储/添加本地存储)、[对接 Ceph 存储](https://docs.idcsmart.com/docs/魔方云/4.%20磁盘与存储/对接Ceph存储) | 官方搜索正文可读；单页打开遇到 4 MiB 获取上限。确认本地/Ceph 与节点关联的管理思路，不声称完整读过其中全部命令。 |
| R12 | [本地存储热迁移](https://docs.idcsmart.com/docs/魔方云/9.%20插件与增值功能/9.3%20本地存储热迁移) | 官方搜索正文可读；单页打开 cache miss。确认开机迁移、能力/硬件匹配、节点/磁盘迁移区分，未采用其 SSH 凭据流程。 |
| R13 | [克隆实例及创建为模板](https://docs.idcsmart.com/docs/魔方云/3.%20管理实例/克隆实例及创建为模板) | 官方搜索正文可读。模板/克隆与原实例独立；磁盘不可缩小。 |
| R14 | [磁盘扩容](https://docs.idcsmart.com/docs/魔方云/3.%20管理实例/磁盘扩容) | 单页目录及官方摘要可读。宿主磁盘扩容与客户系统内分区/文件系统扩容不能冒充同一完成状态。 |

读取限制：网络、存储、迁移等大章节汇总页返回内容过大，未把获取失败写成“已通读”。R1 对轻量版第二网卡 OVS/VLAN 的一行说明与末段“无 OVS”存在表述不一致；这里只采用明确列出的加强版能力，不推断其私有实现。R1 没有证明隧道选型、控制面算法或所有功能的可用性等级。下面网络架构与约束属于**本项目设计**，不是对方实现披露。

## 3. 状态定义与代码锚点

- `implemented-partial`：仓库存在某个受限实现和自动测试，不代表完整目标或实机验收。
- `missing`：没有可交付实现；目标字段、按钮、fake runner、示例配置不能替代功能。
- `in-development`：本轮正在开发，须通过独立测试后更新记录；不计入已交付。
- `realhost-required`：需要真实 Ubuntu/KVM/交换或存储条件验收。可与前述状态并列。当前所有会实际改变 VM、数据盘、宿主网络的能力均有此门槛。

当前代码锚点（路径相对 `aster-cloud/`）：

| 锚点 | 文件/入口 | 已有边界 |
| --- | --- | --- |
| A1 | `internal/control/config.go`、`store.go`、`admin_create.go` | root 审批节点/preset，资源预留、能力/心跳门槛；不是网页完整节点/区域 CRUD。 |
| A2 | `internal/nodeproto/contract.go`、`internal/hypervisor/engine.go`、`ledger.go` | 创建及电源任务、精确请求摘要、独占 journal、未知结果隔离、受限删除。 |
| A3 | `internal/hypervisor/config.go`、`network.go`、`engine.go:prepare/domainXML/seed` | 旧 normal 路径的单 IPv4 静态配置、预配置专用 Linux Bridge、确定 MAC、固定防欺骗 filter；该旧路径无租户安全组、VLAN 或 VPC。 |
| A4 | `internal/hypervisor/doctor.go`、`internal/nodeproto/capabilities.go` | 只读探测与受 root 上限约束的能力公告，不自动改宿主。 |
| A5 | `internal/nodeproto/storage_contract.go`、`internal/hypervisor/storage_engine.go`、`storage_manifest.go`、`qcow_header.go` | 旧普通网络实例的停止态单系统盘快照/备份；OVS 实例拒绝旧存储合同，不能丢绑定恢复。 |
| A6 | `internal/control/migration_transfer.go`、`operation_runner.go`、`internal/hypervisor/storage_transport.go` | 旧普通网络实例的四阶段冷迁移；OVS 尚无绑定存储/迁移合同，明确拒绝；不是热迁移/HA。 |
| A7 | `internal/identity/`、`internal/control/console.go`、`audit_query.go`、`internal/diagnostics/` | Secure Cookie/CSRF、明确 RBAC、审计精确分页、白名单日志。 |
| A8 | `frontend/src/pages/`、`components/OperationActions.vue`、`MigrationWizard.vue`、`composables/mutation.ts` | 管理员实例/节点/任务/审计/用户 UI；待确认写入防重；不是客户 SSO 或 VNC。 |
| A9 | `internal/control/resource_view.go`、`../vps-billing/backend/controllerapi/` | 独立只读资源视图与既有财务开通协议；不把控制台用户 ID 猜为财务客户。 |
| A10 | `internal/nodeproto/metrics_contract.go`、`internal/hypervisor/metrics.go`、`internal/control/metrics.go`、`frontend/src/components/InstanceMetricsPanel.vue` | owner/node/实例绑定的实时只读样本；缺值为 null、累计计数为十进制字符串，非历史监控/计费账本。 |
| A11 | `migrations/005_network_ipam.sql`、`internal/networking/`、`frontend/src/pages/NetworksPage.vue` | MySQL VPC/地址池/租约及管理台；planned/reserved，不执行宿主网络或自动释放。详细合同见 [NETWORK_API.md](NETWORK_API.md)。 |
| A12 | `internal/fabric/`、`cmd/aster-network/` | 保留 root CLI 的单宿主 OVS 微分段/双向 meter；本轮新增嵌入式 Activate/Deactivate/Check/Inspect，EX flock 跨隔离、TAP 核验、apply/readback 和 resume。 |
| A13 | `plugins/billingconnector/`、`cmd/aster-billing-plugin/` | 复用原公开协议和安全 transport 的独立资源适配 CLI；不是支付插件，不由财务 runtime-plugin manager 加载，不替代财务原生持久任务。 |
| A14 | `migrations/006_instance_network_bindings.sql`、`internal/control/network_tasks.go`、`internal/networking/store.go:ReserveTaskTx`、`internal/nodeproto/network_binding.go`、`internal/hypervisor/ovs.go` | 006 引入的事务内 IPAM/任务绑定、node/2 不可变网络规格、节点 schema-3 所有权及 OVS 生命周期门禁。 |
| A15 | `../vps-billing/docs/RESOURCE_PLUGINS.md`、财务 runtime resource worker/manager | 新增 manager 管理的 `resource.aster-cloud` 0.1.1 transport（`aster.resource/1`；最低Core **0.5.10**，Core已正式发行而worker仍为独立候选；旧正式0.5.9不支持），接原持久开通任务；与 A13 CLI 是不同交付物，不绕过原 job claim/幂等或付款边界。 |
| A16 | `internal/overlayproto/`、`internal/control/overlay_*`、`internal/fabric/overlay_*`、`internal/hypervisor/overlay*` | schema-7 全局 VPC/epoch、固定 VXLAN peer、受控路由、reserved 成员创建屏障、显式恢复；不是实际跨宿主连通性验收。 |
| A17 | `internal/fabric/nat_*`、`internal/overlayproto/nat.go`、`frontend/src/pages/OverlayNetworksPage.vue`、`OverlayEpochPage.vue` | root 批准 namespace SNAT/TCP/UDP DNAT、后台完整成员/路由/NAT 及恢复；限制与权限见 [NETWORK_MANAGEMENT.md](NETWORK_MANAGEMENT.md) 和 [NAT.md](../internal/fabric/NAT.md)。 |

## 2026-10-24 公网 IP 增量

新增 A18：`migrations/008_public_ips.sql`、`internal/control/public_ip_*`、
`frontend/src/pages/PublicIPsPage.vue`。已实现公网 IPv4 NAT 专用池、追加库存、
全局唯一租约、实际出口选择、完整解绑确认回收、权限与审计，见
[公网 IP 管理](PUBLIC_IP_MANAGEMENT.md)。该增量引入 schema 8；既有迁移不改。
该段为 schema8 NAT 增量，后续 schema9 能力见下段；IPv6、热迁移或物理路由自动发布仍未实现。下面原 A11 的
网关/DNS/分组差距仍在；不能用新 NAT 出口租约冒充原创建地址可任意释放。

## 2026-10-24 VM 公网直绑及浮动 IP 增量

新增 A19：`migrations/009_public_ip_resources.sql`、`internal/control/public_ip_resource_*`、
`internal/nodeproto/direct_public.go`、`internal/hypervisor/direct_public.go`、
`internal/fabric/floating_ip.go` 及管理台对应组件。schema9 与 node journal5；
旧 NAT 租约和历史合同不改。新建普通网络 VM 真正使用指定公网 IP，已有 VM 仅停止态
同 IP/MAC 接管；浮动 IP 为独立 owner/VPC 资源，通过全组 epoch 连接目标专属
SNAT/整地址 DNAT，可移动到同 VPC 的跨节点成员。普通直绑冷迁移保持 IP/MAC，
支持单独确认源退役后的回迁；不冒充 VPC guest 磁盘迁移或热迁移。
见 [完整合同与限制](VM_PUBLIC_IP_MANAGEMENT.md)。真实 KVM/上联仍 `realhost-required`。

## 2026-10-24 浮动 IPv4 公网入站规则增量

新增 A20：`migrations/010_public_ingress.sql`、`internal/control/public_ingress*`、
`internal/overlayproto/public_ingress.go`、`internal/fabric/floating_ip.go` 及管理台实例入站规则组件。schema10 将策略与地址
绑定分离：新绑定默认拒绝未经允许的新入站，显式允许 IPv4 来源、协议和端口；策略
跟随实例，不随浮动 IP 移动。完整策略版本、root 批准、新鲜能力与全节点 epoch
共同约束生效状态，历史 legacy 快照不重写。它不覆盖东西向、IPv6 或普通直绑，
不是完整安全组。见 [公网入站合同](PUBLIC_INGRESS.md)。真实宿主与公网上联仍待验。

## 4. 加强版核心网络差距（最高优先级）

R1/R4/R5/R6/R7/R10 是功能依据；具体执行器选型须再查 Ubuntu/libvirt/OVS 上游资料并在专用宿主验证。

| 目标能力 | 当前状态/锚点 | 本项目待补交付及验收门槛 |
| --- | --- | --- |
| 地址池与分组、前缀/网关/DNS、节点适用范围 | `implemented-partial` A3/A11：集中 IPv4 池与租约已实现 | 单节点、显式 1–4096 地址、网关及批准节点；实库并发/幂等/权限/分页已测。DNS/区域组/IPv6/编辑/释放尚缺；预留不等于公网生效。 |
| 多 IPv4、IPv6、多个 IP 限速组 | `missing`；A2 严格拒绝不支持规格 | 能力显式匹配，逐地址/组唯一绑定。IPv6 RA/NDP/DAD、路由、反欺骗实测；不得仅接受字段而忽略执行。 |
| OVS 数据面 | `implemented-partial` A12/A14；旧 A3 仍是 Linux Bridge；`realhost-required` | 已接显式 VPC 的 DB/node/VM 启停门禁，固定 profile SHA、domain/TAP/interface UUID，跨回调 EX flock、drop→paused/link-down→exact readback→resume；失败保留不确定。专用桥仍须 root 独立准备；不改财务网卡，真实隔离/重启验收延期。 |
| 按 IP 上下行限速、IP 组共享及混合策略 | `implemented-partial` A12/A14：显式 node/2 VPC 单 IP 双向 drop meter；旧 normal 仍拒绝非零带宽 | 新 VPC 绑定要求双方向显式 1–100000 Mbps，IPv4=1/IPv6=0、无流量计费；Mbps×1000=kbps。不是排队整形、IP 组共享或流量额度；真实吞吐/突发/重启待测。`realhost-required`。 |
| VLAN 隔离 | `implemented-partial` A11 的 node/VLAN 唯一预留 + A12 的 VPC metadata 微分段 | 当前用 VLAN 编号作 bridge 内 OpenFlow metadata 标签，并非已提供 802.1Q trunk/access；来宾 tagged frame 默认 drop。物理 802.1Q 上联/跨节点 VLAN trunk 仍 `missing`；A16 的 VXLAN 不能冒充它，不能把 OVSDB tag 当显式 flow 隔离。 |
| 节点内/跨节点私网 | `implemented-partial` A12/A16；`realhost-required` | 已实现固定 VXLAN peer/VNI、MTU 约束、精确 ARP/IPv4 身份与全节点 epoch 屏障，无 flooding/LOCAL/NORMAL。运营者须提供受信 underlay；双宿主 VM 包流、欺骗/速率与连续故障恢复仍待真机验收。 |
| VPC、子网、路由及客户归属 | `implemented-partial` A11/A12/A14/A16/A17 | 已有原 IPAM 冻结绑定、全局 VPC、root 批准网关目的前缀、跨节点成员、创建屏障及后台完整配置/恢复。planned/reserved 不等于已联网；完整子网生命周期、自助网络、动态路由与真机包流验收仍缺。 |
| 浮动/弹性公网 IP | `implemented-partial` A18/A19；`realhost-required` | 独立直绑/浮动资源、全局互斥、确认分配/解绑/回收、同 owner/VPC 跨节点成员切换、普通直绑地址保持冷迁移。运行中热换主 IP、多公网 NIC、VPC 磁盘迁移/HA 未实现；物理验收后置。 |
| NAT 端口转发/共享建站 | `implemented-partial` A17/A18；`realhost-required` | 已有 root 批准的公网 TCP/UDP/ICMP echo 出站、精确 TCP/UDP DNAT、源/端口校验、全节点屏障、规则读回与 conntrack 撤销。A18 接池、分配、实际地址选择和确认回收；IPv6/hairpin/ICMP DNAT、域名共享建站及真实上联/KVM 验收仍缺，不占宿主 SSH/财务端口。 |
| 租户安全组 | 完整安全组仍 `missing`；A20 已实现[浮动 IPv4 公网入站规则](PUBLIC_INGRESS.md)，不是完整 VPC/直绑/IPv6 安全组 | 已有受限来源/协议/端口、版本/默认拒绝和全节点确认。完整入/出方向、东西向、优先级、IPv6/ARP/NDP 及真实故障验收仍缺。 |
| IP-MAC 绑定与反欺骗 | `implemented-partial` A3/A12；`realhost-required` | 旧 bridge filter 和新 OVS exact IP/MAC/ARP+VPC metadata 与嵌入 gate 分别有测试，不互相替代。必须实测同桥非托管端口、ofport 重用、双标签、宿主服务攻击及断电恢复。 |
| DHCP | `missing`；A3 当前使用 NoCloud 静态地址 | 地址授权绑定、租约与持久 IPAM 一致；隔离 rogue DHCP，重复 DISCOVER/请求/租约恢复、DHCP 服务故障不能重复发放地址。 |
| 负载均衡 | `missing` | owner/VPC 资源、监听器、后端、健康检查、证书生命周期；后端/探测不可借机访问管理网。先交付明确协议范围，故障后旧配置继续工作。 |

**不能把旧基础 profile 改名为增强 profile。** 旧 node/1 `normal` 保持原来的批准 Linux Bridge 与默认带宽语义；只有明确 root profile、精确 owner/IPAM 绑定、匹配 capability 的 node/2 任务可走新 VPC 门禁。数据盘、IPv6、流量额度、多 IP 及未审批路由/跨节点意图仍明确拒绝。0 带宽只表示旧合同中批准的默认模式，不能转成任意正限速。

## 5. 主控及被控其余功能矩阵

| 功能域 | 当前状态/锚点 | 距离完整目标与验收 |
| --- | --- | --- |
| 原生 Ubuntu22/24 安装/doctor | `implemented-partial` A4 | Ubuntu22/24 单独验证 libvirt/QEMU、权限、AppArmor、systemd、TLS、干净安装/升级/卸载保留数据；当前没有实机完整认证。`realhost-required`。 |
| 区域/节点组/节点、容量、维护、排空 | `implemented-partial` A1/A4/A8 | 网页区域/节点组 CRUD、受控纳管/证书轮换、版本兼容、排空流程待补；心跳过期不调度、容量并发无超卖、维护不删除实例。 |
| 实例创建/电源/删除 | `implemented-partial` A1/A2/A8 | 真实引导/SSH/关机/强停/删除/重启不确定恢复待实机。启动成功不得推断客户应用就绪。批量操作须逐个稳定 ID/状态，不全批冒充成功。 |
| 暂停/恢复、锁定、回收/恢复 | `missing` | 与真实 libvirt 状态分开，锁定有明确权限，回收保留磁盘/地址及保留期；清理任务未知不自动删资源。 |
| 变更客户/归属迁移 | `missing` | 原 owner 与新 owner、磁盘/VPC/安全组/地址依赖的原子约束；审计前后归属；不能修改历史账单客户快照。 |
| CPU/内存变配与磁盘扩容 | `missing` | 资源增量事务预留、允许的停机影响、磁盘只增不缩、失败后真实配置读回；系统分区扩容单独报告。 |
| 内存超售/KSM 与资源超分策略 | `missing` | 默认不超售；若支持，须管理员显式设置物理/承诺/预留上限，OOM/balloon/租户干扰监控与回退；不能沿用参考的性能宣传直接开启。 |
| 审批镜像、公钥及初始化 | `implemented-partial` A2/A3 | root 批准哈希、静态 NoCloud；镜像目录/版本/撤销、Windows 支持、克隆模板、重装/救援/ISO 待补。禁止任意宿主路径/下载 URL/客户命令。 |
| 密码重置/guest agent | `missing` | 单独能力与镜像适用性、加密传输/短期秘密、guest 成功证据、失败不显示成功；日志/审计/浏览器缓存不可保留密码。 |
| 应用预设/初始化脚本 | `missing` | 只允许运营者审查并版本化的 guest 预设，明确镜像/动作/时限/结果校验；客户字段不得变为宿主命令，不记录或任意导出应用凭据。 |
| 本地池、独立数据盘、IOPS/吞吐限额 | `implemented-partial` A2/A5：仅批准系统盘本地目录 | 磁盘独立对象、挂载/卸载、容量/配额、IO 限额和断电恢复待补。磁盘归属/路径硬边界、空间不足不得破坏原盘。 |
| Ceph/共享存储 | `missing` | pool/image 与密钥最小权限、节点能力、RBD 锁/fencing、读写路径、备份一致性及故障演练；不可上传 Ceph admin key 到普通网页。 |
| 快照/备份手动操作 | `implemented-partial` A5/A8；`realhost-required` | 仅旧普通网络实例的停止态全量系统盘、同实例恢复；OVS 拒绝旧 storage/restore 合同。运行中一致性、增量、数据盘及真实数据/引导恢复仍待补。 |
| 定时备份/保留/异地恢复 | `missing` | 稳定计划 run ID、错过运行策略、锁/配额、已验证恢复点再剪枝、对象存储凭据隔离；演练原盘损坏及完整恢复。 |
| 冷迁移 | `implemented-partial` A6/A8；`realhost-required` | 旧普通网络实例四阶段链已有；OVS 明确拒绝旧迁移路径，待绑定网络的存储协议。双宿主数据/网络与断电验收仍缺，源未知持续 fence/占位。 |
| 热迁移/磁盘热迁移/HA | `missing` | CPU/QEMU/网络/存储能力前置；目标预留、唯一启动权、可恢复进度和故障 fencing。不能把文件复制进度或 QEMU 指令 ACK 当迁移成功。 |
| 实例实时 CPU/内存/磁盘/网卡读数 | `implemented-partial` A10；`realhost-required` | 只读链及管理面板已实现，测试 raw domstats、单位、NULL/uint64、owner/node 绑定、pending 拒绝、陈旧内存和切换迟到；GET 不推进任务。**尚未真实 libvirt/KVM 采样，不是历史监控或客体健康证明。** |
| 历史图表/流量周期/额度/超额策略 | `missing` | 累积计数重启/回卷/迁移语义、采样去重、方向/周期、缺样显示；自动限额动作另经幂等任务；不直接改变财务金额。 |
| 告警/滥用策略 | `missing` | 租户/管理员收件权限、持续阈值和恢复、通知去重/失败重试；自动资源动作需可审计批准，不通过监控 GET 隐式强停。 |
| 管理 UI/RBAC/用户/审计 | `implemented-partial` A7/A8 | 已有管理路径；MFA、客户 SSO、客户级隔离自助页面、作用域 API key 待补。每个新增权限默认拒绝且 admin 明确获得；动态撤权及时生效。 |
| 受控 VNC/控制台 | `missing` | 一次性短期票据、owner 与实例绑定、Origin/权限验证、连接撤销；不能暴露宿主 VNC 端口或把 root 密码交财务。 |
| 日志/任务/排障/运维 | `implemented-partial` A7/A8 | 安全 JSON 日志和审计查询已有；告警外送、留存落地、磁盘满、节点故障、备份还原及升级回滚实机演练待补。 |
| 财务资源产品兼容 | `implemented-partial` A9/A13/A14/A15/A16 | 原持久财务 job/request/result/快照不变；新增 manager 管理的 resource transport，不是支付插件、无 HTTP fallback。主控显式批准的 VPC 任务可走新绑定链；新增实例已接全节点 reserved epoch 后再创建，原财务字节不变；续费/自动挂起及真 VM/跨宿主验收仍缺。见 [RESOURCE_PLUGINS.md](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RESOURCE_PLUGINS.md)。 |
| GPU/其他增值能力 | `missing` | 计入范围盘点，但后置；IOMMU 组/硬件独占、设备重置与回收安全须专用硬件验收，不伪造 capability。 |

## 6. 分批交付依赖（不是并行堆按钮）

```text
现有稳定操作/归属/RBAC/能力边界
  ├─ P0 只读 metrics（受限链已实现，待实机）→ 后续历史采样/告警
  └─ P1 MySQL IPAM + 管理 UI（管理对象仍 planned/reserved）
       └─ P2 DB事务绑定→node/2→专用OVS VM启停gate（本轮代码接通）
            ├─ P3 单 IP 双向 meter（已接显式VPC任务）→ 组限速/多 IP/IPv6/采样
            └─ P4 全局VPC/固定peer跨节点/批准路由（已接代码；子网/DHCP待补）
                 └─ P5 namespace NAT/公网出口/后台配置（已接代码）
                      └─ P6 公网库存/直绑/浮动IP/受限入站（已接代码）→ LB/客户自助网络

P1 资源模型 + 现有持久任务
  └─ S1 独立磁盘/扩容/IO → S2 调度备份/恢复 → S3 Ceph
       └─ 与 P4/P5 网络迁移能力汇合 → M1 热迁移/HA
```

- P0 不能绕过 P1–P5。实时读数可独立交付，但计数器不是可靠计费账本；没有历史库不能标“任意时段图表”。
- P1 的管理对象 create 成功仍只代表计划/预留；只有 P2 显式 VPC 创建任务才有同事务绑定与节点执行，二者不能共用“已联网”状态。
- P2 的独立 CLI 限定运营者预备并 root 标记的专用整桥/TAP，绝不把 Linux Bridge profile 改名为 OVS。显式确认整桥后，端口未知可触发整桥 drop 隔离并中断全部端口；foreign controller/flow 不接管。只读 VerifyLive 不修复、不 quarantine，是点时观察而非永久启动授权。本轮嵌入 gate 则持有同一 EX flock 跨实际 VM 回调；不能拿 CLI 历史回执代替它。
- 存储及生命周期工作可与网络并行，但热迁移必须等待地址绑定、网络隔离和唯一启动权；不能先做“迁移成功”的按钮后补 fencing。
- 每批同时交付前后台、接口文档、权限/审计、失败状态、旧协议回归和可复现验收。未支持项明确不可选，不向用户暴露“开发模式/数据来源”等测试设置。

## 7. 本轮具体实现与下一步集成门槛

### 7.1 已落地的 IPAM 管理核心

Migration 005 新增 `controller_network_vpcs`、`controller_network_pools`、`controller_network_leases`，未改 001–004。写事务共用 `controller_lock.id=1`，审计同事务；数据库列类型/符号/排序规则/索引形状都要核对。VPC owner/node/CIDR/VLAN 受约束；地址池显式数组上限 4096、IPv4 数值排序；租约唯一键同时约束 pool+address 和 node+address。

`/console/v1/networks/{vpcs,pools,leases}` 提供 create/list/按原 ID detail；实际 Console 写须同时拥有 `nodes.read` 与 `nodes.manage`。Idempotency-Key 即资源 ID，canonical 强类型意图/actor/kind 绑定，同 key 变意图 409。池分页既受 100 条又受约 512KiB 预算，不能用“少于 100 条”断言最后一页。丢 ACK 后只能按原 ID 查询，不能换 ID 再建。

管理对象状态仍为 `planned` / `reserved`，没有 delete/free/自动到期回收，不改历史资源或财务快照。Migration 006 的 `controller_instance_networks` 和 `ReserveTaskTx` 将显式 VPC create 的 IP 预留、不可变网络绑定、精确任务 SHA 与审计纳入同一个事务；提交后才派发 node/2。旧管理 API/实库证据不能替代新 gate 或包转发验收；本轮实测与跳过项见 [OVS_VM_GATE_VALIDATION.md](OVS_VM_GATE_VALIDATION.md)。完整 API 见 [NETWORK_API.md](NETWORK_API.md)。

**升级/回滚：当前主控数据库为 schema 11；001–010 历史 SQL 不改，旧二进制不能只换程序回滚。** 007 引入全局 VPC/epoch，008/009/010 分别引入公网库存、VM 公网资源和实例入站策略，011 仅新增成员分页索引。必须停写、备份，采用兼容应用或已演练的完整一致恢复路径。没有自动删除网络表/租约/策略版本的降级迁移；任何恢复都必须保留已占地址和未知任务，不能当作清理重试。详见 [主控运维](../deploy/controller-OPERATIONS.md)。

### 7.2 从独立 OVS 核心到显式 VM 门禁，仍不是完整路由 VPC

`aster-network plan/apply/status/verify/fingerprint` 只操作 root 明确审批的专用 `aster-` bridge，不创桥、改 uplink、装包、搬网卡或运行 shell。静态 topology 为 node+revision+VPC/owner/IP/MAC/stable Interface ID/ofport/双向 Mbps。来宾 untagged IPv4/ARP 先验证源，再凭 VPC metadata+目标 IP/MAC 精确输出；ARP 指向已知 peer，不泛洪。tagged/未知/IPv6/LOCAL 默认 drop。每端口一个 IPv4，各方向分别使用 drop meter；它不是有保证的排队整形、共享组限速或流量账本。

Apply 写前持久意图，整桥 drop 后改 meter，再 bundle allow 并 exact flow/meter/端口映射读回。相同 revision/digest 只返回原回执，未知/崩溃阻止自动重做；ofport 不是身份。已审批整桥出现未知 physical/tunnel/TAP 时可能整桥 drop，这不是“拒绝意味着无宿主写入”的接口。未通过整桥标记或存在 foreign flow/controller 时不接管。

Status 和同 revision replay 是历史回执；VerifyLive 只读最后 applied topology、专用桥、稳定身份、flow 与 meter，返回绑定摘要和观察时间。校验失败无 repair/写入/新回执；成功也只是点时证据，**不是可长期复用的 VM-start 授权**。本轮 VM 启停使用嵌入门禁：EX flock 跨 drop、paused/link-down bootstrap、固定 TAP/UUID/MAC 核验、动态 ofport、allow/meter 实时读回和 resume；停机清除旧 ofport 授权。root 绕开锁的外部修改不能由点时 proof 永久担保。

旧普通网络仍走批准 Linux Bridge；新显式 VPC 使用 node/2 + schema-3 节点 journal，fabric gate 首次写 schema 2，归档/overlay 使用 schema 3；节点显式网络恢复 completion 升 schema 4。新实现保留旧 schema 读取但旧 binary 不得忽略新绑定与 NAT owner 墓碑。OVS 旧 storage/restore/migration 和旧电源 reconcile 明确拒绝；不能以 domstate running 覆盖 fabric 未知状态。

门禁自动测试使用受控 runner、真实私有文件约束及故障注入；**没有真实 OVS/KVM 隔离、吞吐、重启或攻击包验收**。实际自动化、实库、Linux 插件结果分别见 [OVS_VM_GATE_VALIDATION.md](OVS_VM_GATE_VALIDATION.md)，不在此复制未完成的测试数字。细节见 [fabric README](../internal/fabric/README.md)。

### 7.3 本轮已接通与下一步不可冒充的能力

1. **已接通的绑定**：显式 VPC 创建在主控同事务冻结 owner+instance+node+lease+pool+VPC+profile SHA，原请求摘要不重写。普通网络及历史对象不补写网络语义。
2. **已接通的启动/停机边界**：node/2 完整标量 NetworkBinding；root profile 选择保护好的本地 fabric config，wire 不携带 root 路径。Activate/Deactivate/Check 处理真实生命周期门禁，不使用历史 receipt 授权；OVS reboot 需显式 shutdown/start。
3. **仍需真机验收**：专用单节点双租户的抓包、反欺骗、速率、端口重用、重启与故障，之后才可声称实际客户网络可用。用户延期真 KVM，不表示已通过。
4. **仍缺安全释放/轮转**：旧数据面解绑且无迁移/恢复依赖后，才能另行确认审计释放。删实例、禁用节点、客户取消或查不到回执都不是释放租约证据。
5. **已接跨节点、路由/NAT 与公网资源**：固定 VXLAN peer/VNI、全节点 epoch、批准路由、namespace SNAT/DNAT、显式公网 IPv4 出口、地址库存/直绑/浮动 IP 与受限入站规则已有实现；[OVERLAY_DESIGN.md](OVERLAY_DESIGN.md) 是当前合同，不再仅为设计。DHCP/DNS 服务、自动配置 underlay、负载均衡及真实跨宿主/公网上联验收仍缺。公网始终受管理网/特殊地址隔离与独立 root 批准约束，不提供任意协议或无限制出口。当前边界见 [NETWORK_MANAGEMENT.md](NETWORK_MANAGEMENT.md)、[VM 公网资源](VM_PUBLIC_IP_MANAGEMENT.md)及 [PUBLIC_INGRESS.md](PUBLIC_INGRESS.md)；逐轮证据见[验证入口](VALIDATION.md)。

### 7.4 已移除累计 64 次变更上限，保留历史围栏

旧版本每桥 64 条 topology / lifecycle 记录上限属于历史限制。当前采用 32 条活动页和不可变 SHA 链归档，保留原身份、操作/请求摘要、历史精确 replay 与未解决结果围栏；overlay phase/local lifecycle 使用独立持久记录，不复用旧 64 条数组。NAT owner 与 journal 墓碑不能靠删除配置/文件清除。

损坏、缺失、权限或落盘无法确认时仍拒绝继续，不删历史、不仅保留最新 receipt，不用换状态目录绕过。完整历史校验有随运行时间增长的磁盘/I/O/内存成本；长期规模、备份恢复及真实故障验收仍是上线门槛，不宣传无限容量。见 [fabric 恢复说明](../internal/fabric/RECOVERY.md)。

## 8. 每项完成门槛与发布口径

同一项功能保留四份互不替代的证据：

1. **代码/契约**：输入/输出、能力、权限、持久模型、幂等、失败/未知状态与兼容说明完整。
2. **自动测试**：单元/race/构建/静态检查/安全扫描、真实 MySQL迁移/并发/恢复；明确跳过项与已知依赖例外。
3. **真实宿主**：Ubuntu22/24 的 VM/数据面执行及崩溃/丢响应/重启/磁盘满/证书过期；网络功能须双租户、双节点、抓包/吞吐和管理链路存活证据；备份恢复须实际数据与引导一致。
4. **真实 UI/运维**：同源 HTTPS真实 API，手机/桌面实际截图；干净原生安装、升级、备份还原、回滚、安全权限及日志留存。

用户将第 3 项延期时，可交付开发代码和第 1/2 项结果，但状态仍保留 `realhost-required`。不能将“main 已推送/CI 绿/页面有按钮/命令退出 0”写为完整 KVM 加强版已上线。现财务 Release 不因主控功能盘点被覆盖；主控正式发行需单独列明版本、能力、验收与未支持项。

当前实现/协议边界同时参见 [ARCHITECTURE.md](ARCHITECTURE.md)、[CONSOLE_API.md](CONSOLE_API.md)、[NODE_README.md](../NODE_README.md)、[VALIDATION.md](VALIDATION.md)、[OVS_VM_GATE_VALIDATION.md](OVS_VM_GATE_VALIDATION.md) 及财务 [RESOURCE_PLUGINS.md](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RESOURCE_PLUGINS.md)。

### W07-A：成员列表完整分页

主控成员页从固定最早100人补为稳定游标上一页/下一页，原users.manage、admin与有界委派不变；不代表MFA、客户SSO或可配置财务权限组已完成。完整测试与未验边界见[成员分页](MEMBERS_PAGINATION.md)。
