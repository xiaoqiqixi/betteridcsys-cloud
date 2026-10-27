# 公网 IP 库存、分配与 NAT 绑定

本文记录 schema8 的 NAT 租约合同，保持原操作与历史证明不变。后续 schema9 的
VM 真直绑、浮动 IP、迁移及独立资源 API 见 [VM 公网管理](VM_PUBLIC_IP_MANAGEMENT.md)。
两者共享全局地址占用，不允许 NAT 与 VM 各自分配同一 IP。

本轮基于 main `6498480`，按“地址段 → 库存 → 客户分配 → 出口绑定 →
确认解绑 → 回收”的管理流程实现，不对接第三方 API。仅改主控/被控网络，
不改金额、支付、原财务资源请求、原实例创建绑定或既有网络快照。

## 管理台操作

入口：**网络与 IP → 公网 IP**。读取要求 `nodes.read`，所有写动作同时要求
`nodes.manage` 和 `instances.manage`，沿用同源 HTTPS 会话、CSRF/Origin、
事务审计。不接受宿主网卡、命令、namespace 路径或任意外部 API 地址。

1. **新建地址池**：选择集群，填写名称、CIDR，输入连续 IP 范围或逐个地址。
   只允许纳入该集群独立 root 批准的公网地址，地址须在 CIDR 内；最多 4096
   个。不同池的 CIDR/库存全控制器互斥，不能借另一个节点或池重复占用。
2. **补充地址**：在原池使用“补充地址”。仅追加批准地址，仍属于原 CIDR，
   不删除已有库存、分配记录或创建操作回执。不需要创建重叠地址池。
3. **分配地址**：从池选择 VPC 和 NAT 出口；客户归属取自精确 VPC/root
   网关身份，不靠手填客户 ID 猜测。可指定地址或自动分配。自动分配在同一
   锁定事务中跳过已有租约、旧隐式出口及未确认网络引用，最后一个地址并发
   只能分配一次。分配只是预留，不会暗中替换当前出口。
4. **绑定出口**：前往对应 VPC 的“配置网络”，在“公网地址绑定”选择已分配
   给这个 VPC/节点/profile 的 IP，再设置 SNAT 和出口范围、确认并提交。
   实际冻结的 `nat_policies[].public_ipv4` 驱动 SNAT、Internet SNAT 及 DNAT，
   不是 UI 展示字段。节点三阶段完整确认后才显示绑定完成。
5. **启停池**：停用仅阻止新分配，不断开既有 NAT。启用仍重核 root 批准。
6. **回收**：在 VPC 网络配置中移除该 NAT 绑定并完成全部节点的准备/应用/
   放行，之后才能输入准确 IP 确认回收。仅关闭 SNAT 不等于解除 DNAT 或整份
   NAT 策略。pending、unknown、rejected、部分回执不能当作安全解绑。
7. **保留历史**：回收只释放独立的 active 占用，原租约保留为 `released`，
   原操作结果固定不变。重新分配产生新 ID，不重用旧租约身份。

页面显示“已分配尚未绑定 / 已绑定 / 变更待确认 / 暂不可回收 / 已回收”。
库存数不是空闲数：旧隐式出口可能占用一个尚无新租约的地址；不能仅用
`pool.addresses - leases` 猜测可分配数。最终以锁定事务的确认结果为准。

## 节点执行与批准

原 `public_ipv4` 仍是缺省地址，新增私有批准字段：

```json
{
  "public_ipv4": "<原批准地址>",
  "public_ipv4s": ["<附加批准地址1>", "<附加批准地址2>"]
}
```

这只是字段示意，不是可直接运行的配置。附加列表最多 64 个、去重/排序，
不含 primary、uplink、管理/underlay/VPC/特殊用途地址。controller 对应
`overlay_clusters[].nat_profiles[].public_ipv4s` 必须与节点实际批准一致，
且 NAT profile SHA 必须为真正完整配置摘要，不能手编测试 SHA。

所有地址仍须由运营方实际持有并路由到对应专用出口。outside 接口允许
root 批准地址的已配置子集，但 primary 和本次选中地址必须存在；内外接口、
精确默认路由/下一跳、namespace FD/inode、独占归属与规则读回继续严格核验。
批准或租约存在不等于地址已配置、上游已路由或真实 Internet 已连通。
后台不改宿主管理网卡、默认路由、防火墙，不凭输入的 IP 抢占外部地址。

全部批准池地址（含未选中的备用地址）和快照中其它显式公网绑定都进入公网
fallback 排除。更换出口通过原 epoch 屏障与 conntrack 撤销清除旧连接；
旧地址的 SNAT/DNAT 不继续接流。未配置的新地址、非法源、漂移或部分失败
必须拒绝并保持隔离，不把执行错误算成功。

## 迁移与兼容

- 主控增加 schema **8**：公网池、append-only 库存、历史租约、全局 active
  唯一占用、固定结果操作日志。严格 schema 预检、重入/漂移检查；不修改
  005/006/007 已发布迁移内容或原财务 schema。
- 新 `NATPolicy.public_ipv4` 和 root `public_ipv4s` 缺省保持旧 canonical 字节与
  摘要；指定地址必须匹配 root 批准和精确 reserved 租约。数据库记录不扩权。
- 扩大 root 批准列表会改变完整 SHA。沿用已有 previous pin + 显式恢复迁移，
  不能仅更换 config 然后普通派发；完整步骤见 [网络管理合同](NETWORK_MANAGEMENT.md)。
- 旧默认地址不能凭当前配置猜历史归属。完整历史中无法解析的旧 pin 被视为
  潜在占用；只有最新更高 epoch 的全部精确 release 回执且当前不再引用地址，
  才覆盖此前未知状态。真实旧 SHA → 新 SHA 的恢复路径有实库回归，不增加
  HTTP 可写影子 root 授权目录。
- 池纳入旧 primary 时记录当时既有隐式政策的不可变基线，允许原政策连续保留；
  一旦移除/改动不能重新隐式使用。池创建后全新默认出口不允许绕过分配。
  安全转换为显式管理需要先完整解除旧绑定，再分配和显式绑定。

## API 与确认语义

所有 POST 使用独立 `Idempotency-Key`，操作 ID 绑定 actor/action/target/
完整 canonical request。资源变更、库存/active、固定结果日志和审计在同一
`controller_lock` 事务提交，审计失败整体回滚。配置规划、恢复、实例预留
与最后一次实际 dispatch 都重核租约和 root 批准。
实例自动预留携带仅存在内存中的完整集群 root 解析上下文：其它集群正常使用
不同公网地址不应阻塞创建；相同地址或无法核实的旧 pin 仍拒绝。这个上下文
不进入财务请求、节点请求或历史快照。

| 接口（前缀 `/console/v1/public-ips`） | 用途 |
| --- | --- |
| `GET /options` | 完整有界的集群、VPC、root 允许地址 |
| `GET /pools`、`GET /pools/{id}` | 库存清单/详情 |
| `POST /pools` | 创建池，201 |
| `POST /pools/{id}/addresses` | `{addresses:[]}` 追加库存，200 |
| `POST /pools/{id}/state` | `{enabled:bool}` 启停分配，200 |
| `GET /leases`、`GET /leases/{id}` | 历史及当前绑定/回收条件 |
| `POST /leases` | 精确分配或 `address:""` 自动分配，201 |
| `POST /leases/{id}/release` | `{}` 确认回收，200 |
| `GET /operations/{id}` | 当前 actor 原操作固定结果，不查询可变资源猜成功 |
| `GET /operations` | 当前 actor 的操作分页记录 |

列表按 ID 升序，以 `cursor` 翻页，`next_cursor:null` 为结束；每页最多100项且
JSON ≤1MiB，大池/大操作记录按字节预算分页，游标不跳项。完整 options 不截断
后谎称 complete，超过1792KiB安全失败。独立公网 JSON 上限128KiB以容纳4096
地址，保留严格未知/大小写/重复字段和日期校验，不放宽原64KiB接口。

浏览器发送前持久保存完整非秘密意图；丢响应后暂停该账号的新地址写入，只
GET 原操作并核对 actor/action/target/request/result，不能关弹窗、改草稿或刷新
就重发。网络错误、404、存储损坏、外来结果不能冒充原操作成功。

## 验证与限制

- 单元/实库：并发末 IP、跨池/CIDR重复、越 root/VPC/owner/node、显式未租
  地址拒绝、隐式旁路、pool禁用、追加库存、回收历史、ACK固定结果、审计回滚、
  profile迁移、未知/部分回执、超过64个历史epoch、JSON与响应预算。
  双集群实库回归同时覆盖后台与财务触发的实例预留，不跳过跨集群隔离校验。
- Ubuntu22/24 原生强制入口：真实第二IP TCP/UDP SNAT/DNAT、地址切换撤旧
  TCP/映射、禁用和解绑、缺地址安全拒绝。只在隔离namespace/veth内跑。
- 真实MySQL浏览器：原5版本/30唯一POST后新增创建池、补充、丢allocation ACK、
  GET原操作、绑定、pool启停、完整解绑、回收、重新分配。最终应为7epoch/
  42唯一nodePOST/7公网操作/2历史租约，原30前缀及旧bytes不变。
- 本地Darwin无MySQL/原生Linux条件的skip明确不算验收；最终同提交CI记录另存
  `artifacts/public-ip-pool-20261024/`，不能套用旧6498480绿色CI。
- 不宣称整个KVM加强版功能已全部完成；其余差距仍见
  [功能矩阵](KVM_ENHANCED_PARITY.md)。本文 schema8 增量仅为公网 IPv4 NAT 出口管理，
  不包含 VM 直绑/浮动 IP；后续 schema9 已另行实现受限的[VM 公网资源](VM_PUBLIC_IP_MANAGEMENT.md)，
  不能由本页旧轮次的七 epoch 测试推定通过。IPv6、任意多公网网卡、热迁移、
  动态上游 BGP/ARP 发布或 NAT HA 仍未实现。
- 真KVM、跨物理节点、真实公网/上联、物理重启和生产部署验收按要求后置。
  财务服务器本轮不作为网络实验机，也不进行真实付款。

本轮实际查阅的参考：[添加IP](https://docs.idcsmart.com/docs/魔方云/7.%20网络与安全/添加IP)、
[NAT转发与建站](https://docs.idcsmart.com/docs/魔方云/7.%20网络与安全/NAT转发与建站（单IP与NAT分开）)。
汇总页打开遇到4MiB限制，使用官方检索返回的正文，不声称通读全部实现细节；
本项目独立实现，未使用第三方源码/API/品牌或安装脚本。
