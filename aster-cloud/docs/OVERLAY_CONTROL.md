# 全局 VPC、成员 epoch 与恢复

本文描述独立 `aster.overlay/1` 控制合同。它不替换 `aster.node/2` 的原创建请求，不修改订单、金额、币种、支付、商品配置摘要或历史财务快照。网络操作的完成只表示参与节点确认对应阶段；不是端到端 VM 连通、网关 NAT 或真实 KVM 验收证明。

## 对象与权限

- **全局 VPC**：同一 cluster 中的 owner、私有 IPv4 CIDR 和唯一 VNI。与已有 node-bound local VPC 分开，不能混用 VLAN 与 VNI。
- **成员**：引用原实例、节点、local VPC、pool、lease、原 `NetworkBinding.Digest()`，以及原 IP、MAC、interface UUID、双向限速。全局 IP 在 VPC 内唯一，成员 identity/lease/IP 不随网络 epoch 改写。
- **epoch**：全量 VPC、所有成员（包括禁用成员）、root profile pins、路由网关和可选 NAT 策略的不可变快照。完整快照 SHA 和前一快照 SHA 固定在数据库中。
- **Reserved 成员**：已在同一数据库事务中保留实例和原 IPAM 绑定，但尚未向节点发送创建任务的未来成员。不是已经创建/运行的 VM。创建完成后可以在下一 epoch 清除 `reserved`；未创建时不可清除。
- **恢复 epoch**：新 operation ID、新 epoch；原成功、失败或未知快照与所有原节点 receipt 保留。只增加 `superseded_by` 关联，不将旧未知 receipt 改为成功。

所有管理端接口仍使用同源 HTTPS session 和 CSRF。读需要 `nodes.read`；创建全局 VPC 另需 `nodes.manage`；规划/推进/核对/恢复 epoch 同时需要 `nodes.manage`、`instances.manage`。因为准备阶段会隔离并暂停已存在成员，只有网络只读或仅节点管理权限不能执行。

## root 绑定与新增实例

主控 root 配置新增可选 `overlay_clusters`：

```json
{
  "cluster_id": "private-a",
  "profiles": [
    {"node_id": "node-a", "profile_id": "vpc-a-v1", "profile_sha256": "<完整 overlay root 配置的 SHA256>"},
    {"node_id": "node-b", "profile_id": "vpc-b-v1", "profile_sha256": "<另一节点完整 overlay root 配置的 SHA256>"}
  ],
  "mappings": [
    {"node_id": "node-a", "local_vpc_id": "<32位原local VPC ID>", "vpc_id": "<32位全局VPC ID>"},
    {"node_id": "node-b", "local_vpc_id": "<32位原local VPC ID>", "vpc_id": "<相同全局VPC ID>"}
  ]
}
```

先创建全局 VPC，再由 root 配置 local→global mapping；手工成员规划、恢复 replacement 和自动新增使用同一映射，不能只凭 CIDR 相同改投另一个全局 VPC。一个 node/profile 不能同时属于两个独立 cluster。root pins 指向新 overlay 配置，原单宿主 fabric 配置及其 binding SHA 保留；不能通过换 root 配置绕过正在进行的 epoch。

普通财务或管理端创建选择到该 profile 时：

1. 在原实例/IPAM/容量/任务事务内写入原 node/2 binding。
2. 基于上一已完成 epoch 和 root mapping 生成完整新 epoch，新增 `reserved=true` 成员；原财务与 node/2 请求字节不变。
3. 自动网络 epoch 全部节点完成 release 之前，原 create 保持 `accepted`，其 claim 返回状态冲突，不向节点 POST。
4. `aster-controller serve` 的后台 overlay runner 只推进未发送网络任务，并在 epoch 完成后调用原 worker 创建未来成员；原创建结果语义不变，不伪装“定义好但未启动”为成功。
5. 节点异步返回 `accepted` 后，后台 runner 对相关 `sending/dispatched/uncertain` 创建继续进行原 operation ID + request SHA 的 GET-only 核对，直至记录实际终态；不会因超时、服务重启或未知结果重 POST。该只读跟进也覆盖 overlay 成员后续 power/delete 结果，原财务 GET 不变。待发送和待核对队列分别按 ID 有界轮询，维护、心跳过期或未知节点上的首个任务不会永久饿死另一可用节点；claim 仍走原节点串行锁。
6. 没有明确 mapping、地址冲突、前一 epoch 未确认、遗漏同 profile 活实例，都拒绝本次 admission，并回滚整个事务。

没有原 IPAM 租约的客户端输入不能通过填 IP/MAC 直接入网；API 只接受实例 ID 和 VPC ID，从数据库重建其余身份。

后台已提供 VPC 创建、成员/路由/NAT 配置、阶段任务、只读核对与显式恢复。root 网关/NAT 安全投影、候选实例、迁移批准状态及字段边界见 [后台网络管理合同](NETWORK_MANAGEMENT.md)，节点私有审批见 [NAT 执行合同](../internal/fabric/NAT.md)。

## API

基址 `/console/v1/overlays/`：

| 方法/路径 | 作用 |
| --- | --- |
| GET `clusters` | 已批准 cluster ID 与节点 ID；不暴露凭据/URL/宿主路径 |
| GET `options?cluster_id=…` | 批准 profile/映射/网关/NAT、完整实例候选和最新 epoch；不暴露私有 namespace/路径 |
| POST `vpcs` | 创建全局 VPC；`Idempotency-Key` 为 32 位小写 hex ID |
| GET `vpcs?cluster_id=…` | cluster 的全局 VPC；root 上限 32，不截断无提示 |
| GET `vpcs/{id}` | 按原创建 ID 查询完整 VPC，用于未知 ACK 核对 |
| POST `epochs` | 冻结完整成员、网关与 NAT 快照，返回 202 |
| GET `epochs?cluster_id=…&before_epoch=…` | 按 epoch 降序分页；`next_before_epoch` 继续访问历史 |
| GET `epochs/{id}` | 不修改节点，返回冻结快照、每个节点阶段状态 |
| POST `epochs/{id}/advance` | 启动异步后台推进；key 必须等于 epoch ID，body `{}` |
| POST `epochs/{id}/reconcile` | 只 GET 一个原未知任务的精确 receipt，不重 POST |
| POST `epochs/{id}/recover` | 以新 key 建新恢复 epoch；body 为 `{"expected_snapshot_sha256":"…"}`；可选完整 `replacement` 见下文 |

创建 VPC 的 body：`cluster_id, owner_ref, name, cidr, vni` 全部必填。

普通 epoch 的 body：`cluster_id, expected_epoch, members, gateways` 全部必填。成员为 `instance_id, vpc_id, enabled, reserved`；空数组必须写 `[]`，不能用 `null`。网关采用 `overlayproto.Gateway` 的固定实例/接口/IP/MAC/prefix，只有节点 root 明确批准且实时身份核对成功才可执行。网关允许前缀不可覆盖任何 VPC CIDR；host、underlay、metadata 等保护前缀由节点继续验证。该合同允许从 root 批准网关选择目的前缀子集或移除网关；不自动部署物理上联或无限制 Internet 路由器。

可选 `nat_policies` 支持批准 namespace 的 IPv4 SNAT / TCP、UDP 单端口 DNAT；省略保留上次策略，显式 `[]` 清除，`null` 拒绝。每个 VPC 最多一份策略，目标必须是同 VPC 已启用冻结成员；端口、来源和目的前缀不能超出 root 批准。完整形状见 [NETWORK_MANAGEMENT.md](NETWORK_MANAGEMENT.md)。旧不含 NAT 的规范快照与摘要保持不变。

接口采用精确字段名、禁止未知/重复/null 字段。任务使用规范 JSON 字节计算 SHA。数组顺序不构成新成员意图。相同 key 不同 actor 或不同 body 返回冲突，不更换既有 reservation。

## 三阶段和故障

1. **prepare**：每个参与节点先持久记录意图并隔离整桥、核对/暂停完整本地 inventory。
2. **program**：仅全部 prepare 确认后开始；各节点编程并读回完整规则，VM 仍不放行。
3. **release**：仅全部 program 确认后开始；各节点核对并放行被允许成员；NAT namespace 在完整规则核验和全节点 program 屏障后才开启 forwarding。

没有“多数节点成功”的 quorum 规则。任务先持久 `sending`，再一次性 POST；HTTP 超时、断连、异常 receipt 都是 unknown。重启不会重发 sending/uncertain。overlay 采用独立 110 秒总超时/100 秒响应头预算，保留固定 DNS/CIDR、mTLS pin、禁代理/重定向/静默重拨；原节点协议的 10/6 秒预算不变。后台单 epoch 最长 30 分钟、最多 4 个并发协调器。

未知可以先按原 task ID、request SHA 只读核对。无法确认时显式 recover：并行读取全部批准节点实际 head，将每节点 `{node_id,cluster_id,epoch,snapshot_sha256}` 固定到新恢复任务，然后重新全组 prepare→program→release。允许某节点仍在更早 epoch，或从未收到任务而 head 为空；不允许猜测、未来/外来 head 或重用错误 SHA。获取 head 后发生并发变化会被节点 exact-head fence 拒绝，需新一轮显式恢复，不能静默改 head。

若旧快照因错误网关或目的前缀被 root 拒绝，原样恢复仍会拒绝。操作员可明确提交新完整选择，不必永久卡在原错误意图：

```json
{
  "expected_snapshot_sha256": "<被替代的最新 epoch SHA>",
  "replacement": {
    "members": [
      {"instance_id":"<原实例ID>","vpc_id":"<root映射批准的全局VPC ID>","enabled":true,"reserved":false}
    ],
    "gateways": []
  }
}
```

`replacement` 不提供时保持原快照恢复；提供时必须同时写完整 `members`、`gateways`（不是 merge patch），二者的 `null`、缺字段、重复字段均拒绝；可选 `nat_policies` 的省略保留/显式空数组删除语义同普通 epoch。它复用普通 Plan 的 owner/profile/mapping/IPAM/原 binding/全量 inventory 与唯一 IP 校验：不能省略仍未确认 deleted 的实例，不能修改原 node/2 identity、租约或财务字节；已归属成员的 unknown 生命周期由新恢复 epoch 和节点实际 ledger 再隔离核验。cluster、预期旧 SHA 与全部观察 head 不可借 replacement 变更。root pins 不能从 HTTP 指定；普通恢复沿用批准 pin，仅节点与主控都明确审批旧→新 pin 的恢复可生成当前新 pin，详见 [配置迁移](NETWORK_MANAGEMENT.md#为已有集群启用新的-root-nat-配置)。新 canonical snapshot SHA 以 `overlay.recovery.replacement` 审计，target 为 `<新operationID>:<新SHA>`；旧 snapshot 和失败 receipt 原样保留。前缀依然必须通过节点 root 的保护范围与实时核验，绝不因“恢复”放宽策略。

原 release 失败可能已有部分 VM 运行；因此恢复不能仅把一个节点的旧 receipt 改成成功，而必须重新隔离所有参与节点。即使主控最新 epoch 为 `succeeded`，后续 OVS 重启或成员生命周期故障也允许以精确 SHA 显式建立恢复 epoch；旧成功 receipt 仍原样保留。已被替代或不是最新的 epoch 不能重新取得控制权。主控不宣称多宿主事务原子性。

## 数据库与验收

schema 007 新增四张独立表：`controller_overlay_vpcs`、`controller_overlay_epochs`、`controller_overlay_tasks`、`controller_overlay_members`。migration 执行前后检查 InnoDB、精确列/字符集/唯一索引，允许正确部分 DDL 重入，拒绝 view、丢失唯一性和冲突表结构。全局成员 IP/lease 约束与 epoch/任务/审计在同一 InnoDB 锁事务中提交。

测试入口：

```sh
go test -race ./internal/overlayproto ./internal/control ./internal/networking
# 设置隔离的真实 MySQL 测试 DSN 后（不能是生产库）：
go test -race ./internal/control -run '^TestMySQLOverlay' -count=1
```

未配置 DSN 的 skip 不是 MySQL 通过。故障测试包含成功 epoch 后续故障恢复、错误网关拒绝后的明确 replacement（含 SHA 审计和事务回滚）、双节点 blocked/eligible 公平队列、all-node barrier、丢 ACK 无重发、只读核对、多轮恢复的落后/空 head、原快照不变、审计失败整体回滚、真实 TLS/CSRF/RBAC，以及财务/管理两条新增链先冻结 Reserved epoch 再允许 create。本轮 NAT/后台管理的精确实测与跳过项见 [NAT_NETWORK_VALIDATION.md](NAT_NETWORK_VALIDATION.md)。真实两台 KVM/OVS、路由流量、MTU、重启和故障注入仍需另行宿主验收，不能由 fake RPC、SQL 或隔离 namespace NAT 测试替代。
