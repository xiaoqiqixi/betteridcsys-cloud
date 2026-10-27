# 跨节点私网：配置与恢复

目标是原生 Ubuntu 22.04 / 24.04、libvirt/KVM、OVS OpenFlow14。代码与离线解析通过不等于两台宿主已验收；未做真实流量、MTU、故障与恢复演练前，保持节点维护，不接真实客户。

## 配置顺序

1. 停止新的资源派发，备份**独立主控库**及每个节点完整 node/fabric 状态目录。保留所有归档、overlay 操作和恢复证据，不能只复制 `journal.json`。将数据库迁移到 schema 007；旧 binary 无法读取新 schema。
2. 在独立 underlay 上准备固定节点地址和正确 MTU，验证其隔离/认证措施。VXLAN UDP 4789 自身没有认证。不要使用现有财务服务器的管理桥作为租户桥，也不要为省事修改宿主默认路由。
3. 每个节点的原 fabric 配置继续使用原 bridge/state directory 和 SHA；新 overlay 配置 `base` 必须与其完全相同。参考 `overlay-private.example.json`，将文档保留地址替换为真实批准地址，完整列出所有 peer、管理网及受保护 CIDR。示例两个 ack 均为 false，**故意不能直接执行**；确认专用桥和可信 underlay 后才由 root 批准。
4. 对称配置 peer 列表，每个参与节点都有一份配置和独立 SHA。`guest_mtu <= underlay_mtu - 50`；1500 underlay 的示例使用 1450 guest。已有 1500 MTU VM 不会静默改写，必须事先完成独立受控迁移/配置；仅改 root 字段无法使旧 TAP 通过验收。
5. 配置保存为 root 所有、0600、单链接、不可由其他用户写入的普通文件。只读计算规范摘要：

   ```sh
   sudo /opt/aster-cloud/bin/aster-network overlay-fingerprint \
     --config /etc/aster-node/fabric/private-overlay.json
   ```

   输出为协议、node ID、SHA，不读写 bridge 或 VM。不要用文件字节的 `sha256sum` 代替规范对象摘要。原 `fingerprint` 仍用于原单宿主 `NetworkBinding` SHA，两者不可混用。
6. 节点原 `ovs_profiles.<profile_id>` 保留 `fabric_config` 与 SSH 策略，增加 `overlay_config` 指向新文件。主控 root `overlay_clusters` 固定 cluster、每节点 profile ID 与 overlay SHA；原 `network_profiles` 不换 SHA。
7. 使用有 `nodes.read` + `nodes.manage` 的管理会话创建全局 VPC。已存在的每节点 local VPC 必须具有相同 owner/CIDR；然后在 root `overlay_clusters[].mappings` 固定 local VPC → 全局 VPC。不要手写 SQL 绕过唯一性和审计。
8. 如果接管已有实例，用 `POST /console/v1/overlays/epochs` 提交完整成员和批准网关，核对全部节点三阶段结果。新实例由原创建事务自动预留完整成员 epoch，**全部节点 release 后**才发送原创建任务。未确认的网络不会被演示数据或 accepted 状态伪装为成功。接口字段、权限与分页见 [控制合同](../docs/OVERLAY_CONTROL.md)。

每个 node/profile 只能归属一个 cluster；不同桥也不能复用有歧义的 VXLAN 接收端点。overlay 模式启用后有持久墓碑，不能删除 owner 文件或切旧 CLI 恢复成未初始化桥。root 配置不是在线可随意修改的 UI 参数：未完成 epoch 必须保持原 pin，变更要有单独停写/迁移方案。

## 路由

`gateways` 必须是已准备好的、具有精确 VM/TAP/interface/owner/IP/MAC 的 router appliance；所有节点批准同一网关列表。`allowed_prefixes` 只给业务所需目的网段，不能覆盖管理网、underlay、任一 VPC、metadata 等保护范围，不能使用 `0.0.0.0/0` 绕过这些限制。

`guest_networks` 将本节点原 local VPC/owner/CIDR 对应到该网关及相同前缀，用于**新建 VM** 的 NoCloud 路由与 MTU。网关自身 forwarding、返回路由、防火墙和所需 NAT 必须单独配置和验收；本系统不会自动把宿主变成 Internet 网关，不会更新旧 seed 或财务商品快照。

## 失败处置

- 无响应、发送中、uncertain：先按原 epoch/task ID 只读 reconcile，不重新 POST 原动作，不释放未知 IP/容量。
- OVS 丢失 flows、部分节点 release、节点生命周期失败：从最新 epoch 发起新 key 的显式 `recover`，固定其 snapshot SHA。主控会读取所有节点实际 head 并冻结，重新全组准备、编程、放行；并发 head 变化必须拒绝，不静默重试。
- 恢复不能通过“running”猜测一个不存在的创建已成功，也不会重跑旧创建、销毁、关机命令。原 VM 已存在且身份和实际目标电源状态可证明时，才允许显式完成对应未知生命周期；未知磁盘/迁移操作必须走其独立恢复合同。
- 日志/归档缺失、磁盘不可持久化、外来接口、所有权变化、无法确认 DROP 时均保持未确认，停止派发。禁止删 journal、改 epoch/receipt 或放宽验证来解锁。
- 单宿主桥另用 `aster-node --network-recovery-status` / `--recover-network`；overlay 桥拒绝本地单节点恢复，不能绕过集群屏障。

## 升级、备份和回滚

主控 schema 007、fabric schema 3、节点恢复 completion 所需 schema 4 和新的恢复文件是同一次版本升级的一部分。备份必须在停止派发并确保日志一致时包含独立主控库、各节点完整 journals/archives/overlay/recovery 文件和批准配置，以及原磁盘/制品备份。不能回滚财务数据库，更不能修改历史订单快照。

旧 binary 回滚必须恢复配套版本的可信独立库和节点状态，并核对备份之后发生的 VM/IP/存储变化；简单恢复旧数据库可能重新分配仍被 VM 使用的地址。没有经过真机恢复演练，不提供自动“一键回滚成功”承诺。
