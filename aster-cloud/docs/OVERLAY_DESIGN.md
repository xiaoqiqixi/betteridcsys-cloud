# 路由、跨节点 VPC 与恢复合同

本页描述 **main 开发版已接入的实现**，不是 KVM 宿主或生产连通性验收报告。真机验收按用户要求延期。代码不改变财务金额、币种、支付、订单幂等或历史商品配置；原 `aster.node/2` 创建请求及 IPAM 绑定也不重写。

## 执行链

`管理 API / 创建实例事务 → schema 7 全局 VPC、epoch、任务 → 主控后台 worker → pinned mTLS → 节点 → 同一 OVS fabric 锁 → libvirt NIC / VM`。

独立网络合同为 `aster.overlay/1`。root 明确批准的 `OverlayClusters`、每节点 `OVSProfile.overlay_config` 和完整配置摘要是必要条件。没有配置的旧单宿主网络保持原义。

- 全局 VPC 单独分配 VNI，保留 owner、CIDR；成员引用原 lease、pool、local VPC 和完整 `NetworkBinding` SHA，不能只靠 MAC/IP 认领。
- 全量 snapshot 包含所有参与节点 profile pin、成员、网关及可选 NAT 策略。每个节点检查本桥完整 inventory，不接受省略现有实例或改写租约。
- 新实例在原创建/IPAM事务中产生明确的 `reserved` 成员授权。所有节点完成该 epoch 后，才派发原创建任务；节点 paused/link-down 启动、TAP 身份核验、flow/meter 编程读回后才 resume。不存在的预留成员不产生本机放行规则，更不算 VM 已创建。
- 同一专用桥的旧 CLI、单宿主 gate 和 overlay 不得并行覆盖规则。持久模式 pin 与同一个 flock 阻止退回旧 executor；删除 `overlay.owner` 不会恢复成未初始化桥。

## 三阶段与未知结果

1. **prepare**：先持久记录意图、隔离整桥，再将本地自有活动 VM link-down / pause，验证现有接口，建立固定 peer 隧道。
2. 全部节点 prepare 确认后 **program**：安装、精确读回 flows/meters/接口映射；客户 VM 仍暂停。
3. 全部节点 program 确认后 **release**：再次核验，按快照放行 VM，再次读回并持久记录结果。

这不是跨机器原子事务。某节点 release 成功、另一节点失败仍可能出现部分放行；主控必须报告 `uncertain`，不能声称整个集群成功。新任务写前 claim；发送丢 ACK 后只 GET 查询原 operation ID + request SHA，不自动重新 POST。精确历史回执不是持续有效的启动许可。

### 集群显式恢复

`POST /console/v1/overlays/epochs/{id}/recover` 使用**新的 Idempotency-Key**，提交精确 `expected_snapshot_sha256`。主控先读取每节点受 mTLS 保护的只读 head，再在事务中固定这些 head，创建新的 recovery epoch；可选完整 `replacement.members/gateways` 及可选 `replacement.nat_policies`，原 SHA 与实际 heads 不变，详见 `OVERLAY_CONTROL.md`。

主控最新 epoch 已 `succeeded` 时，后续 OVS 重启或普通成员生命周期失败也可显式恢复；仍保留所有旧成功 receipt，不能恢复已被替代的旧 epoch。

恢复任务包含每节点精确预期 head（也允许尚未收到故障 epoch 的空/较旧 head）。节点 head 变化就拒绝；不能在执行时自动重新读取并更新授权。新 epoch 重新执行全组 prepare → program → release。旧 snapshot、请求和回执保留；旧 epoch 以 `superseded_by` 关联新恢复，不把原 unknown 擦成成功。再次恢复失败仍需新批准，不自动循环重试。

### 单宿主 OVS 故障恢复

单宿主使用 root-only `aster-node --network-recovery-status PROFILE` 读取精确 journal / operation / revision / digest，然后通过 `--recover-network /root/approval.json` 执行新恢复意图。服务必须停止，让节点 ledger 保持独占。

批准文档协议 `aster.node-network-recovery/1`，包含新的 `operation_id`、`original_operation_id`、`profile_id`、完整 `expected`、`enabled_instances`。JSON 为规范紧凑序列化，文件 root 私有，不接受重复/大小写别名字段。恢复从本地原 ledger 重建完整同桥意图，先保存原始不确定结果证据，隔离、暂停、动态解析 TAP/ofport、重编程、读回、放行。它不重跑创建/销毁命令，不重建丢失 VM，不绕过陌生端口或域 XML 所有权。

也支持“原节点任务成功，但 OVS 重启丢规则”的恢复；不改写已成功原任务。故障创建/启动仅在新恢复实际证明其目标状态后完成原操作，并保留原始记录。恢复完成还需独立 node journal completion，与整组旧操作的收敛一次 CAS/save；只有旧任务本来已成功或只存在结果文件不能冒充本轮完成。首次写入 completion 升级节点 journal 到 schema 4，旧 binary 必须拒绝读取。磁盘写入/回调/读回失败均不视为成功。overlay 桥必须使用集群恢复，不能用本地命令绕过多节点屏障。

## 数据面边界

### VXLAN

- root 固定 local/remote IPv4、UDP 4789、专用桥、接口派生身份及 MTU；不接受 `remote_ip=flow`、任意设备/URL 或客户提供的 ofport。
- IPv4 VXLAN 预留至少 50 字节；核对本机 underlay 地址/接口 MTU 和 TAP MTU。新 VM 的 libvirt XML、NoCloud 同时设置 guest MTU。旧 1500 MTU 客户机不会被静默认作 1450，需独立受控迁移/配置。
- 隧道入口精确匹配 peer port、tun_src、tun_dst、VNI、源 MAC/IP/ARP sender。VLAN、IPv6、未知源和未知目的默认丢弃；不使用 NORMAL/FLOOD。
- remote-ingress 位禁止 peer → peer 中转。本地来源 egress、本地目的 ingress 分别使用 drop meter；这不是队列整形或流量计费。
- VXLAN 本身不提供对端密码学认证。运营方必须独立准备隔离或认证 underlay，并在 root 配置中明确批准；`underlay_trusted_ack` 与 evidence reference 不是本系统已配置 IPsec 的证明。[RFC 7348 §7](https://www.rfc-editor.org/rfc/rfc7348.html#section-7)、[OVS VXLAN 文档](https://docs.openvswitch.org/en/latest/faq/vxlan/)

### 受控网关路由

保留**批准 router appliance 的实际受限转发**，并增加 root 预备专用 namespace 的受控 NAT 网关。两者均绑定明确身份和前缀，不提供无限制 Internet 默认出口或自动物理上联。

网关具备固定 VPC/IP/MAC/接口身份和目的 prefix allowlist；appliance 使用受管 TAP，NAT 网关使用单独批准和核验的 veth，不冒充 libvirt VM。客户机仅能向对应网关及批准目的转发，返回流量也受源 prefix 限制。拒绝与任何 VPC、root protected CIDRs、underlay 端点、loopback、link-local/metadata、multicast 等地址范围重叠的路由。网关不能被替换成宿主管理物理网卡。

root `guest_networks` 把 local VPC / owner / CIDR 映射至批准 gateway 和同一 allowlist，供新 VM NoCloud 写入路由。既有 VM 的 guest 路由、appliance 自身配置及运营者提供的外部返回路径仍是部署验收前置条件；不会修改历史 seed、假设客户机已执行配置或宣称公网已通。

### 批准 namespace NAT

`Snapshot.nat_policies` 绑定 VPC、网关、节点和完整 root NAT profile SHA；支持 IPv4 SNAT、TCP/UDP 单端口 DNAT 到同 VPC 已启用冻结成员（包括跨节点成员）。目的与来源前缀、公共端口均受 root 审批和已选路由约束，不支持 `0.0.0.0/0`、IPv6/hairpin NAT、ICMP DNAT 或公共 IP 分配。

NAT 跟随 prepare/program/release 屏障，使用 namespace 内 nft 原子替换、精确读回和 conntrack 撤销；策略修改会中断既有 NAT 连接。失败独立尝试关闭并核对 namespace forwarding，无法确认仍保留 unknown，不重放；root pin/namespace 重建须显式恢复，旧 owner 不能靠删文件或删配置遗忘。后台只操作安全投影，不接受 namespace/宿主路径或命令。完整前置条件与兼容语义见 [NAT 执行合同](../internal/fabric/NAT.md) 和 [后台网络管理合同](NETWORK_MANAGEMENT.md)。

## 归档与容量

原有“64 次变更后停止接受动作”的终身上限已移除。活动页达到 32 条时，以规范 SHA 链归档完整记录，保留所有历史精确重放/冲突检查和 unknown 围栏；不会删 journal 或仅调大数字。

归档损坏、缺失、权限不可信、落盘失败均拒绝继续，而不是丢历史。当前打开时完整核验历史链，有随历史增长的 I/O/内存成本；仍需磁盘容量、备份和长期规模规划，不能解释为无限规模。overlay phase/local lifecycle 使用独立持久操作记录，不复用 64 条数组上限。细节见 [fabric 恢复说明](../internal/fabric/RECOVERY.md)。

## 管理 API 与权限

- `GET /console/v1/overlays/clusters`：已批准 cluster 与节点清单；`GET .../options?cluster_id=...` 返回批准 profile/映射/网关/NAT 投影、实例候选及最新 epoch。
- `POST /console/v1/overlays/vpcs`：创建全局 VPC；`GET .../vpcs?cluster_id=...` 查询该 cluster 的完整有界清单；`GET .../vpcs/{id}` 按原创建 ID 核对完整意图。
- `POST /console/v1/overlays/epochs`：冻结完整 epoch；`GET .../epochs?cluster_id=...&before_epoch=...` 分页查询，响应 `next_before_epoch` 指向下一页。
- `GET /console/v1/overlays/epochs/{id}`：详情和逐节点阶段结果，不派发节点写操作。
- `POST .../epochs/{id}/advance`：异步后台推进；`POST .../epochs/{id}/reconcile` 只读远端原结果；二者 body 为 `{}`，Idempotency-Key 必须等于 epoch ID。
- `POST .../epochs/{id}/recover`：新 key 和精确 `expected_snapshot_sha256` 创建恢复 epoch；可选完整 `replacement.members/gateways` 及可选 `replacement.nat_policies`，原 SHA 与实际 heads 不变，详见 `OVERLAY_CONTROL.md`。
- 读需 `nodes.read`；创建 VPC 另需 `nodes.manage`；规划/推进/核对/恢复 epoch 同时需 `nodes.manage` 与 `instances.manage`。保留 session、CSRF、TLS 与审计；节点接口只接受批准的控制器 mTLS 身份，不能靠前端隐藏按钮实现权限。

`aster-controller serve` 的后台 runner 自动推进持久的未发送 epoch，发送前持久 claim；不会重发 sending/uncertain。完成 reserved epoch 后才调用原 worker 派发对应创建，随后通过原 ID/SHA 的 GET-only 核对收敛异步创建或成员生命周期结果，未知不重 POST。root `overlay_clusters[].mappings` 明确批准 node/local VPC → global VPC，不从客户参数推断归属。已确认删除的实例只从下一个活跃快照移除，原 epoch、绑定和租约历史仍保留。

root 文件示例、规范摘要工具、配置顺序、备份与恢复边界见 [overlay 运维](../deploy/OVERLAY_OPERATIONS.md)。后台现可创建 VPC、编辑完整成员/路由/NAT、查看阶段任务、核对与恢复；字段与权限见 [后台网络管理合同](NETWORK_MANAGEMENT.md)。完整字段与请求示例见 [控制接口说明](OVERLAY_CONTROL.md)、`internal/overlayproto` 和 `internal/control/overlay_*`。root 配置变化会使旧 pin 失效；不要通过编辑数据库、删历史文件、改已有 profile ID 的设备归属来解除门禁。

## 测试与仍需真机验收

源码包含 strict-contract、全阶段屏障、事务回滚、lost ACK 只查询、空/落后 head 恢复、身份/VNI/ARP/路由隔离、MTU、命令/存储故障、超过 64 次变更与重启重放测试。Linux CI 还运行独立真实 MySQL，以及 Ubuntu22/24 原生 `ovs-ofctl` 离线规则解析和真实 meter wire 编码检查；另有 Ubuntu22/24 隔离 namespace 原生 NAT 包流门禁；这些均不是 KVM 双宿主流量验收。本轮具体执行结果与跳过项见 [NAT 与网络管理验收记录](NAT_NETWORK_VALIDATION.md)。

仍需两台独立 Ubuntu22+ KVM/OVS 节点验证 VM 双向数据、错误 peer/VNI 注入、ARP 欺骗、管理网隔离、MTU、meter 丢包精度、OVS/宿主重启、网关返回路由和连续恢复。没有这些证据，不应启用真实客户销售。
