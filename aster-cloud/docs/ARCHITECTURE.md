# 主控 / KVM 被控的功能与验收边界

本文整理当前 main 的代码范围；逐轮执行结果以[验证记录](VALIDATION.md)中对应的精确提交为准。接口、页面或 fake runner 测试不代表生产功能已经验收。操作入口见[使用入门](GETTING_STARTED.md)，后续目标与已实现路径分开列出。

用户指定以 KVM 加强版能力为对标范围；逐项差距、当前代码锚点、网络/IPAM 数据约束及交付依赖见 [KVM_ENHANCED_PARITY.md](KVM_ENHANCED_PARITY.md)。该规格不表示加强版已完成，也不改变下面已有实现和实机验收边界。

## 责任划分

```text
客户 / 管理员
  │
  ├─ 财务：销售目录 → 报价 → 订单/账单 → 验签结算
  │                     │已付且明确发起、不可变产品快照
  │                     ▼ aster.controller/1
  └─ 主控：接纳/审计 → 资源预留 → 调度/任务 → 实际资源状态
                                      │ 普通网络 node/1；OVS VPC node/2；托管直绑 node/3
                                      │ 固定节点、mTLS
                                      ▼
      计算节点（被控）：宿主机 libvirt → QEMU/KVM → 客户虚拟机
```

财务和主控分别维护权威状态。付款成功不是实例已运行，主控接纳不是节点执行成功，节点返回任务成功也不能反向伪造账单已付。资源 ID、目录分类 ID 与远端产品 ID 不互相猜测。财务不获得计算节点 root 权限，节点不获得财务数据库、支付凭据或会话秘密。

## 本轮已实现的代码路径

- 独立 Vue 3 / TypeScript 管理台：登录、实例列表/创建/详情、真实状态读取、节点维护、按编号直达的资源操作任务详情、精确条件审计查询、用户与角色。支持中文/英文、浅色/深色、桌面/手机，加载/空/错误/忙碌态；没有演示数据回退。
- 响应式导航：52px 一体顶部导航，不宽于 1024 CSS px 使用紧凑入口和抽屉；资源表/连续清单与可收起操作区域适配桌面和手机。键盘目标、焦点回归、背景 inert、滚动锁和跨断点历史清理分别验证；具体源码和截图以验证记录为准，不继承旧侧栏证据，也不是物理手机验收。
- 管理会话：Secure / HttpOnly / SameSite Cookie、固定 HTTPS Origin、CSRF、登录限流、数据库实时权限、会话撤销、最后管理员保护。admin 包含全部明确权限；operator / viewer / custom 在后端逐动作校验，不能靠隐藏按钮授权。
- 实例管理：审批 preset 创建、开关机、重启/强制关机、删除与持久化幂等任务。管理员创建是资源动作，不造财务订单。确认删除才回收相应节点的资源预留，迁移源遗留盘继续保守占位。
- 快照/备份：仅旧普通网络合同下已停止的自有实例，创建、校验、恢复、删除；扁平 qcow2、尺寸/哈希与签名 manifest 校验、原盘恢复保留、限额与故障留痕。不是运行中一致性快照、定时异地备份或跨存储通用实现。OVS 实例拒绝旧 `aster.node.storage/1`，不能恢复时丢掉网络绑定。
- 四阶段冷迁移（旧普通网络实例）：源停止并持久 fence → 固定双向 mTLS 流式转运和目标审批 → 目标导入且停止 → 显式激活。目标容量预留、源/目标双节点互斥、资源映射冻结；不接受任意 URL、宿主路径、XML 或命令。目标默认不开放控制器 inbox 审批，须由 root 明确配置与 pin 源证书。
- 不确定恢复：写前持久意图；断线、响应丢失、进程重启保留 sending / uncertain。核对仅 GET，绝不自动补 PUT/POST。转运部分完成且缺审批时须 root 核查，不能凭文件存在自动导入或启动。
- 财务兼容：既有 `aster.controller/1` 六字段开通结果和幂等原样保留，另加 owner 绑定的只读 `aster.resource/1`。账单金额、币种、支付、商品历史快照和财务数据库均不修改；不把管理台用户 ID 自动当客户 owner。
- 实时监控只读链：节点 `aster.node.metrics/1` 读取自有实例 domstats，主控重新验证实例/owner/node，管理台显示 CPU/内存/系统盘/网卡样本。缺值 null、累计 uint64 用十进制字符串；RSS 不冒充来宾已用内存，balloon 过期报告不伪装新数据。GET 不重试写任务、不推进状态，不是历史监控或计费账本；真实 libvirt/KVM 采样待验。
- 集中网络与任务绑定：migration 005 提供 VPC/IPv4 池/租约管理；migration 006 新增 `controller_instance_networks`。显式 VPC 创建在同一个 `controller_lock` 事务内预留 IP、冻结 node/owner/instance/lease/VPC/profile SHA、写任务与审计；旧 normal 路径不变。普通管理 API 的 planned/reserved 仍不是已联网，地址不自动释放，也不改历史产品快照。详见 [NETWORK_API.md](NETWORK_API.md)。
- OVS 核心与节点生命周期门禁：保留此前 root CLI；本轮 `aster.node/2` 的精确网络绑定只映射到本地 root 批准 profile。节点固定 domain UUID/TAP/interface UUID，持久 XML link-down，禁止 autostart/managed-save 绕过；fabric 的 EX flock 跨整桥 drop→paused bootstrap→实际 TAP/ofport 核对→flow/meter 读回→link-up/resume。`Deactivate` 在停机前隔离并移除旧端口授权；已运行 start 走只读 `Check`，不重复 apply。失败保持 uncertain，不自动回退 Linux Bridge 或重试启动。旧仅观察 VM 电源的 reconcile 明确拒绝 OVS。详见 [fabric README](../internal/fabric/README.md) 与 [OVS 集成验收记录](OVS_VM_GATE_VALIDATION.md)。跨节点、批准网关与恢复已通过下述独立 overlay 合同接入，不能由旧单宿主门禁自动推断。
- 跨节点网络与后台管理：schema **7** 的全局 VPC、成员 epoch、固定 VXLAN peer、受控目的路由与全节点 prepare/program/release 屏障已接入原 VM 门禁；新实例先完成 reserved epoch 再派发原创建。后台提供 VPC 创建、完整成员/路由/NAT 配置、逐节点任务、只读核对和显式恢复，未知结果不重 POST。见 [网络控制合同](OVERLAY_CONTROL.md) 与 [后台网络管理合同](NETWORK_MANAGEMENT.md)。
- NAT 执行：root 预先批准的独立 namespace 支持 IPv4 SNAT 与 TCP/UDP 单端口 DNAT，可指向同 VPC 的跨节点 enabled 成员；另有显式批准的公网 IPv4 出站模式，无须逐个配置公网目的前缀，但继续隔离管理网、underlay、元数据与保留地址。精确 nft 读回、conntrack 撤销、批准 pin 迁移和 owner 墓碑均纳入恢复边界。没有 IPv6/hairpin NAT 或自动物理上联。见 [NAT 合同](../internal/fabric/NAT.md)、[公网出口](PUBLIC_NAT_EGRESS.md) 与 [历史集成验证](NAT_NETWORK_VALIDATION.md)。
- 公网资源：schema 8 提供公网池、追加库存、唯一分配、实际 NAT 地址选择与确认回收；schema 9 增加普通网络新实例的 `node/3` 真直绑、停止态同 IP/MAC 接管、同 owner/VPC 浮动 IP 绑定/跨节点成员切换/解绑，以及直绑地址保持冷迁移和显式源退役。数据库分配不证明物理地址所有权或上游连通，不能热换运行实例主 IP。见 [公网库存](PUBLIC_IP_MANAGEMENT.md) 与 [VM 公网资源](VM_PUBLIC_IP_MANAGEMENT.md)。
- 浮动 IPv4 公网入站规则：schema 10 将实例策略与地址绑定分离，新绑定默认拒绝未经允许的新入站；修改策略、切换目标和撤销均冻结完整版本并经过全节点屏障。它只覆盖 VPC 浮动 IPv4 入口，不是完整安全组；旧 legacy 无策略映射不重写且必须明确提示。当前就绪还检查新鲜节点能力和当前 root 批准，不能把历史 ACK 当实时保护。见 [公网入站规则](PUBLIC_INGRESS.md)。
- 财务资源 transport：新增由财务插件管理器管理的 `resource.aster-cloud` 0.1.1 worker（`aster.resource/1`；`core_min=0.5.10`、`core_max_exclusive=0.6.0`），显式选择后接入原持久开通任务，不新增支付渠道，不把 worker ACK 当服务已开通；没有 HTTP fallback。最低Core为0.5.10，已有正式发行；worker 0.1.1仍为独立候选且不在Core六资产中。旧正式0.5.9不含资源协议，不因旧main版本字符串而获得支持。安装/启用/凭据边界见 [RESOURCE_PLUGINS.md](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RESOURCE_PLUGINS.md)。另保留独立财务资源适配 CLI：`aster-billing-plugin` 复用原公开商品/请求/六字段结果协议与固定 HTTPS 安全 transport，显式 send、只读 lookup；不是支付渠道、不由 runtime-plugin manager 加载、不自动证明付款或更新服务，也不替代财务原生持久开通链。详见 [适配器 README](../plugins/billingconnector/README.md)。

机器 API、管理会话、节点 mTLS 是独立安全边界。旧合同冷迁移不是热迁移，源 fence 不经 API 自动解除；任一侧未知时保持占位，不能双启动。

| 状态域 | 当前版本与兼容边界 |
| --- | --- |
| 主控 MySQL | 当前 schema **12**：007 全局 VPC/epoch，008 公网库存/租约，009 VM 公网资源，010 实例入站策略，011 成员分页索引，012 账户 revision 与身份操作回执；001–011 历史迁移保持不可变。绑定、地址占用、策略版本、epoch、身份回执和审计须一致备份。旧 binary 拒绝新数据库，不能只换程序回滚。 |
| 节点 journal | 兼容既有 schema 1/2；node/2 绑定使用 **3**，显式网络恢复 completion 使用 **4**，托管公网绑定与永久退役墓碑使用 **5**。旧节点不能忽略新绑定继续执行；OVS 存储/迁移及旧 reconcile 明确拒绝。 |
| fabric journal | 兼容此前 schema-1 CLI；首次启停门禁写 schema **2**，增加持久 preparing/completed/uncertain 围栏。归档/overlay 使用 schema **3**，NAT owner 与 `nat_profile_ids` 保留所有权墓碑；旧 binary 不得忽略新字段降级。pending/unknown 不允许借历史 applied 回执放行。 |

升级须停写、完整备份，按兼容版本或已演练的数据库/journal 恢复流程处理；不自动删表、删除 journal、释放未知租约或重新生成任务 ID。

这些是实现与测试范围，不是实际虚拟机验收结论。具体 API 见 [CONSOLE_API.md](CONSOLE_API.md)，安装和恢复门槛见 [主控运维](../deploy/controller-OPERATIONS.md) 与 [被控运维](../NODE_README.md)。

## 完整产品目标

| 模块 | 必须覆盖的目标 | 开发和发布门槛 |
| --- | --- | --- |
| 区域与节点 | 区域、节点组、维护/排空、实际在线状态、容量、版本及能力 | 心跳过期不可调度，维护不删除已有实例，容量预留事务并发不超卖 |
| 实例 | 创建、查看、开关机、软重启/强制操作、挂起/恢复、锁定、回收恢复/删除 | 稳定操作 ID、所有权、危险动作二次确认、真实状态读取、重启恢复 |
| 镜像与初始化 | 经哈希批准的镜像、最小磁盘、cloud-init、公钥、重装/救援、ISO | 不执行客户脚本或随意下载；重装/重置密码不得泄露秘密或越权 |
| 磁盘与存储 | 系统盘、独立数据盘、扩容不缩容、IO 限制、本地池、Ceph | 宿主路径边界、备份一致性、空间不足不破坏原盘、存储故障隔离 |
| 网络与地址 | 持久 IPAM、IPv4/IPv6、桥接/路由、VPC、NAT、安全组、反欺骗 | 地址唯一预留；不把 DHCP 网卡等同于指定公网地址；实测租户隔离 |
| 带宽与用量 | 上下行限速、流量方向/周期、历史计量、超额策略 | 不支持的套餐参数必须明确拒绝，不能忽略后仍成功开通 |
| 快照与备份 | 配额、创建、恢复、删除、定时计划、异地存放与恢复演练 | 真实故障和恢复验收，不能把备份命令退出 0 当成可恢复 |
| 迁移与可用性 | 冷/热迁移、能力检查、目标预留、进度与中断恢复 | 不把复制磁盘等同迁移；源/目标未知状态不得双启动 |
| 用户与权限 | 管理员全部明确权限、租户所有权、角色、API 凭据范围、MFA | 默认拒绝、交叉租户回归、最后管理员保护、凭据撤销与审计 |
| 自助控制台 | 实例管理、监控、受控 VNC、错误/加载/空状态、中英与手机 | 独立会话和真实 API，控制台一次性短期票据，无公开 VNC 端口 |
| 运维 | 监控、任务日志、告警、容量、审计、升级/回退、灾难恢复 | 脱敏与保留策略、磁盘满/掉线/重启/证书过期；原生 systemd 和 TLS |
| 财务兼容 | 商品资源映射、已付开通、状态核对、后续续费/挂起策略 | 不改金额、支付幂等、币种及历史快照；账务和资源状态不可互相冒充 |

本轮在既有管理台与普通网络实例/存储路径上，加入受限实时读数、集中 IPAM、显式 VPC 的 DB→node/2→fabric→VM 启停门禁，以及财务 resource transport；后续增加跨节点 epoch、受控路由/NAT 和后台网络管理。集成代码存在不等于真实包转发已验收；协议/race、真实 MySQL、Linux 插件和 fake-runner 的证据分开记录于 [OVS 集成验收记录](OVS_VM_GATE_VALIDATION.md)。本轮 NAT/网络 UI 的实测与跳过项另见 [NAT_NETWORK_VALIDATION.md](NAT_NETWORK_VALIDATION.md)，真实 KVM/OVS 宿主验收后补。未完成项不能上架承诺，所有目标都要逐项经过代码、真实环境与 UI 验收后才改为已完成。

## 宿主机要求和安全

- 当前只接受 Ubuntu 22.04 / 24.04 amd64，两个平台分别验证；Ubuntu 26.04 和未知版本拒绝安装。KVM 要求硬件虚拟化已启用并有可用 `/dev/kvm`；仅看到 CPU flags 不是完整运行验收。
- libvirt / QEMU 使用发行版受支持版本，不固定发行版专属的 systemd daemon 名称；doctor 检测能力，不自动安装包、重启宿主或改公网网卡。
- 计算节点必须是运营者明确准备的计算宿主机。当前 1 GB 测试服务器同时运行财务，不能因开发请求而自动桥接其 SSH 网卡、清空防火墙或占满内存。
- 节点间使用经审批的证书和固定目的地。缺 CA、错误主机名、错误客户端身份、过期证书均拒绝；禁用 TLS 验证不是联调方法。
- 单个操作先记录意图再执行。网络断开、执行进程退出或写结果失败时，不自动清理客户磁盘、不自动下发替代任务。核对只能读取已有操作及真实域状态。

## 实际阅读的参考

- [IDCsmart 魔方云概览](https://docs.idcsmart.com/docs/魔方云)：功能域覆盖参考，不作为接口兼容保证。
- [创建及管理实例](https://docs.idcsmart.com/docs/魔方云/3.%20管理实例/创建及管理实例)：资源准备与生命周期、客户归属参考。
- [添加节点](https://docs.idcsmart.com/docs/魔方云/2.%20区域节点管理/添加节点)：区域与实际计算节点分层参考；不沿用其认证、端口与安装脚本。
- [libvirt Domain XML](https://libvirt.org/formatdomain.html)、[Network Filters](https://libvirt.org/formatnwfilter.html)：实际虚拟机和网卡配置依据。`isolated=yes` 只隔离同桥上同样标记的端口，不等于完整租户安全组；现成过滤器不能替代完整 VLAN/IPv6 安全设计。
- [Ubuntu libvirt](https://ubuntu.com/server/docs/how-to/virtualisation/libvirt/)、[cloud-init NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)：宿主兼容及实例初始化依据。

本轮测试与当前实现状态另列于验收记录。不得将这份目标矩阵写进 Release 作为已交付功能。

## 2026-10-22 测试机检查（历史记录）

2026-10-22，只读检查用户现有测试机得到 Ubuntu 22.04.5 / kernel5.15，存在 `/dev/kvm` 和 SVM/NPT；可用内存约527MiB、磁盘约1.6GiB，且现有财务正式服务运行。尚未安装 libvirt/QEMU，未修改桥接、防火墙或创建客户虚拟机。主控实库使用独立 Unix-socket MySQL，固定256MiB上限；不是复用财务数据库。这是当时的环境记录，不代表本轮 Linux 插件、MySQL 或 KVM 验收结果；本轮结果以 [OVS_VM_GATE_VALIDATION.md](OVS_VM_GATE_VALIDATION.md) 为准。

## 仍未交付的完整产品范围

客户主控 SSO/MFA、受控 VNC、热迁移/HA、定时备份与异地对象存储、独立数据盘/扩容、重装救援、完整子网/路由生命周期、IPv6/完整安全组、负载均衡、IPv6/hairpin NAT、历史带宽计量、排空自动调度、告警/日志外送与保留轮转、无 root 的 API 权限分离，以及生产安装/升级/灾难恢复演练仍未完成。

应用事件已有 JSON 白名单和只读审计筛选；journald 限额仍是可选模板，生产留存/外送待验。区域/节点/preset 信任根仍由 root 私有配置管理，网页不能任意改 endpoint 或上传证书。普通 VPC 管理对象仍是计划/预留，只有显式批准的创建任务走门禁。固定 peer、批准路由、公网 IPv4 出口、浮动 IP 与受限入站规则已有实现，但真实 KVM/跨宿主/公网上联待验；DHCP/DNS 服务、802.1Q uplink、共享 IP 组限速和流量配额仍缺。guest 可使用 root 批准的静态 DNS，不等于交付 DNS 服务。OVS 专用桥及物理上联须独立准备，安装器不改宿主网卡。


## fabric 历史容量与恢复边界

历史版本每桥 64 条 topology / lifecycle 记录的累计上限已移除。当前以 32 条活动页和不可变 SHA 链归档保留精确历史重放、请求身份与未解决状态围栏；overlay 阶段和本地生命周期使用独立持久记录。不能删除 journal、只留最新回执或换状态目录来清除未知结果。

完整历史核验仍有 I/O、内存和磁盘成本，不能称为无限容量；长期规模、备份还原、断电及真实 OVS/KVM 恢复仍须验收。合同见 [网络与恢复](OVERLAY_DESIGN.md) 和 [fabric 恢复说明](../internal/fabric/RECOVERY.md)。
