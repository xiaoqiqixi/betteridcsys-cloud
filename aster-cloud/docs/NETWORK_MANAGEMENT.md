# 后台网络管理合同

本页说明控制器后台的真实接口和审批边界，不代表已经完成真实 KVM、
跨宿主流量或公网 NAT 验收。金额、支付和原始财务 / `aster.node/2`
创建快照不参与网络策略修改。

## 权限与操作

所有后台接口继续使用同源 HTTPS 会话；写操作必须通过现有 CSRF 与
Origin 校验。网络读取需要 `nodes.read`；创建 VPC 还需 `nodes.manage`；
规划、执行、恢复网络变更同时需要 `nodes.manage` 和 `instances.manage`。
角色不能通过网络接口上传宿主路径、namespace 名称、设备号、命令或密钥。

| 接口 | 用途 |
| --- | --- |
| `GET /console/v1/overlays/clusters` | 可管理集群与节点 ID |
| `GET /console/v1/overlays/options?cluster_id=...` | root 批准范围、完整实例候选、最新变更 |
| `GET /console/v1/overlays/vpcs?cluster_id=...` | VPC 清单 |
| `GET /console/v1/overlays/vpcs/{id}` | 按原创建 ID 查询确定结果 |
| `POST /console/v1/overlays/vpcs` | 创建 VPC；`Idempotency-Key` 即其 ID |
| `GET /console/v1/overlays/epochs?cluster_id=...&before_epoch=...` | 有界变更历史与下一页游标 |
| `GET /console/v1/overlays/epochs/{id}` | 冻结意图和每节点 / 阶段结果 |
| `POST /console/v1/overlays/epochs` | CAS 规划完整成员、路由、NAT 策略 |
| `POST /console/v1/overlays/epochs/{id}/advance` | 推进未发送阶段；body `{}`，key 必须等于原 ID |
| `POST /console/v1/overlays/epochs/{id}/reconcile` | 只 GET 查询原节点任务结果，不重发未知任务 |
| `POST /console/v1/overlays/epochs/{id}/recover` | 观察全部节点 head 后建立新的显式恢复变更 |

创建或恢复响应丢失时，浏览器保留原 ID 与完整意图，先 GET 精确 ID，
逐字段比对后才确认成功；不能生成新 ID 静默重试。`202` 只是接受变更，
不是网络已生效。只有全部节点 prepare → program → release 成功才显示完成。
任务 DTO 可带完整经过验证的 `result` 回执；没有回执就没有可推断的成功。

## 可编辑范围

主控 root 配置中的 `overlay_clusters[]` 增加两个可选审批目录：

```json
{
  "gateways": [{
    "node_id": "node-a",
    "instance_id": "11111111111111111111111111111111",
    "interface_id": "由既有网关身份生成的实际接口 ID",
    "owner_ref": "22222222222222222222222222222222",
    "vpc_id": "33333333333333333333333333333333",
    "ipv4": "10.24.0.1",
    "mac": "52:54:00:00:00:01",
    "allowed_prefixes": ["192.0.2.0/24"]
  }],
  "nat_profiles": [{
    "node_id": "node-a",
    "vpc_id": "33333333333333333333333333333333",
    "gateway_instance_id": "11111111111111111111111111111111",
    "profile_id": "approved-nat",
    "profile_sha256": "节点 root NAT 配置的实际 SHA-256",
    "public_ipv4": "198.51.100.2",
    "allow_snat": true,
    "allowed_source_cidrs": ["192.0.2.0/24"],
    "allowed_ports": [{"protocol": "tcp", "start": 40000, "end": 41000}]
  }]
}
```

以上是字段说明，不是可直接运行的宿主配置：接口身份、摘要和文档示例地址
必须替换为实际经过 root 审批的值。私有 namespace / 接口 / 上联等配置仅在
节点 root 文件中；控制器只保存公开投影和完整摘要钉扎，节点仍独立验证。

- 网关身份不可更换；选中的路由必须位于 root 批准前缀内。例如上限 `/24`
  可以选择其中的 `/25`，不能扩大为 `/16`。
- NAT 出口有“仅指定网段”和“公网 IPv4”两种独立模式。前者使用已选目的
  网段；后者在独立 root 批准下允许公网出站，不要求逐个批准 Internet 前缀，
  但仍隔离管理网、underlay、元数据、私网和特殊用途地址，详见
  [公网 NAT 出口](PUBLIC_NAT_EGRESS.md)。不能把 `0.0.0.0/0` 塞进旧路由白名单。
  `allowed_prefixes: []` 是无指定路由，不自动开启公网；`null` 无效。
- DNAT 仅支持 TCP / UDP 的单个公共端口映射；目标必须是同一 VPC 内已启用的
  冻结成员。公共端口、来源网段、NAT profile 摘要都必须匹配批准范围。
  每个 root NAT profile 最多批准 64 段公共端口范围，与节点执行合同一致。
- 新 VPC 若要关联实例，其 ID 应使用 `mappings[].vpc_id` 中尚未创建的批准
  身份。已有实例使用不可变的本地 VPC / IP 租约映射，不能通过 GUI 改写。
- `options.instances` 不省略不符合当前状态的本集群实例；它们包含
  `eligible:false` 和稳定原因码，防止 UI 静默漏掉同 bridge 的受控成员。
  未配置映射时 `vpc_id` 为 `""`，其余身份仍可见。
- 最新快照内已经删除的成员仍以 `INSTANCE_DELETED` 投影，供后台明确移除；
  不根据“未出现在列表中”猜测实例已删除。候选清单最多 128 个未删除实例
  加 128 个当前快照保留的已删除身份，单个新快照仍最多 128 个成员。

公网 IP 池、追加库存、分配回收及实际 NAT 地址选择使用独立后台与 API，见
[公网 IP 管理](PUBLIC_IP_MANAGEMENT.md)。新显式地址必须有精确 reserved
租约，完整解绑回执确认后才回收，不与原实例创建租约混用。

## NAT 的兼容语义

`POST epochs` 和恢复的 `replacement` 可带 `nat_policies`：

```text
policy = {id, node_id, vpc_id, gateway_instance_id, profile_id,
          profile_sha256, snat_enabled, internet_egress_enabled?, public_ipv4?, forwardings:[
            {id, protocol, public_port, target_instance_id, target_port, source_cidr}
          ]}
```

省略 `nat_policies` 表示保留上一份策略；显式 `[]` 表示删除全部 NAT；
`null` 无效。两种有效语义具有不同幂等摘要。旧版不含 NAT 的快照字节和
摘要保持不变；新购实例的自动预留变更同样保留已有 NAT，而不重写历史。

`internet_egress_enabled` 只有 `true` 才写入 canonical bytes；省略或 `false`
保持原前缀模式的字节 / 摘要。公网模式必须同时启用 SNAT，且安全投影
`nat_profiles[].allow_internet_egress` 已批准、`public_ipv4` 是有效公网地址。
管理员可通过现有完整网络变更启停公网，关闭 SNAT 自动关闭公网模式；公网
启用和恢复需单独确认。界面展示实际选择范围和出口 IP，但“已完成”只表示
节点阶段回执已确认，不代表主控已经探测到真实 Internet 连通性。

每个 VPC 最多一份 NAT 策略；最多 32 份策略，每份最多 128 条端口规则。
这些是单次完整意图的有界容量，不是累计 64 次变更上限。
任何原回执、财务快照、原 IP 租约与原创建绑定都不因恢复而被替换。

### 为已有集群启用新的 root NAT 配置

新增 root NAT profile 会改变节点完整配置摘要，不能靠普通策略变更默默
替换。节点必须明确配置旧摘要 `previous_profile_sha256`，控制器相应集群
必须添加 `previous_profiles: [{node_id, profile_id, profile_sha256}]` 指向
同一节点 / profile 的旧摘要，并把 `profiles` 配置为新的实际完整摘要。
此审批不能从后台 HTTP 写入。然后在后台对最新 epoch 发起明确恢复，可
同时选择新增 NAT；只有该恢复生成的新快照采用当前批准 pin。
普通规划与新购实例预留在迁移完成前仍拒绝新旧 pin 混用。
`options.profile_migration_required` 显示是否需要迁移，
`profile_migration_approved` 显示 root 是否已批准旧 pin；未获审批时不能
把“恢复”当作绕过配置批准的按钮。
旧快照、旧任务回执及成员原始 `NetworkSHA256` 保留；未知结果仍须查询，
不能通过再次改摘要跳过恢复过程。

## 验证边界

`overlay_policy_test.go` 验证批准范围、幂等语义和严格 JSON；
`overlay_policy_mysql_test.go`、`overlay_mysql_test.go` 覆盖真实 MySQL 事务、
审计失败回滚、审批撤销、旧策略保留、明确清除、恢复、完整候选、
真实 HTTPS / 会话 / RBAC / CSRF，以及财务和 node 请求原字节不变。
测试必须提供隔离 MySQL fixture；未提供时明确 skip，不能算数据库验收。
节点 namespace / nftables 与真实转发验收由相应原生测试和真机验收分别记录。
