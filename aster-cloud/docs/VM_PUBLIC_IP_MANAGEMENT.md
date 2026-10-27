# 虚拟机直绑公网 IPv4 与浮动 IP

后续 schema10 将地址绑定与实例公网入站规则分离，新绑定默认拒绝未经允许的新入站；
旧 nil ingress 历史保持原字节并显式提示 legacy。详细范围和升级见
[公网入站规则](PUBLIC_INGRESS.md)。本文中“全端口映射”描述原 schema9 legacy 语义，
不应作为新绑定的默认访问授权。

这是独立于原 NAT 出口租约的资源管理合同。原公网池继续共用，地址占用全局唯一；
新的 `direct`、`floating` 资源不复用或重写原 NAT 租约的 JSON、操作结果或历史快照。
本轮只修改主控、被控及其管理台，不修改财务金额、币种、支付或历史商品快照。
原财务 `aster.controller/1` 请求保持原字节；未启用托管直绑的旧节点继续原流程。
已启用托管直绑的节点不会把缺少显式资源的旧财务请求降级为 first-free；当前须由
管理台显式创建/接管资源，财务自动选择直绑资源的产品策略未在本轮新增。

## 两种模式，不混用

| 模式 | 实际执行 | 适用范围 |
| --- | --- | --- |
| 虚拟机直绑 `direct` | 指定公网地址真正进入新虚拟机 cloud-init 静态网络、Linux Bridge NIC 和精确 IP/MAC nwfilter | 独立 root 批准的普通网络，单个公网 IPv4；不是改页面上的 IP 字符串 |
| 浮动 IP `floating` | 独立 namespace 的目标专属出站 SNAT、整地址入站 DNAT，经已有 OVS/VXLAN VPC 转发 | 同一客户、同一 VPC 的已启用实例之间切换；不改 guest 私网地址，不等于 guest 直绑 |

原 schema9 legacy 浮动映射开放该地址的 TCP/UDP 端口和 ICMP echo，以及受限的相关
ICMP 错误；不是任意 IP 协议透传。当前 schema10 新绑定必须固定实例入站策略，
无规则时拒绝未经允许的新入站，放行范围由显式来源/协议/端口规则决定。管理台显示
目标策略版本并要求确认；该受限入口过滤仍不是完整租户安全组，也不取代 guest 防火墙。
私网、元数据、管理网、underlay、保留地址及批准池自身不能借公网 fallback 访问。
已有独立 root 批准的精确网关目的前缀保留原优先级，不因浮动 IP 获得额外目的授权。

## 管理台流程

入口：**网络与 IP → 公网 IP → 虚拟机公网地址**；实例详情提供对应网络入口。
这是运营 staff 管理界面，不是财务客户自助 SSO。
读取需 `nodes.read`，写入还需 `nodes.manage` 和 `instances.manage`。
所有写入保留 HTTPS 同源会话、CSRF、Origin、精确客户/节点/VPC 校验和同事务审计。
浏览器不能传 bridge、XML、宿主路径、命令或上游 API 地址来扩权。

1. **分配**：在已启用池中选择模式和批准目标，可指定地址或自动选空闲地址。
   原 NAT 租约、VM 公网资源、旧隐式出口和未确认历史引用共同参与占用判断。
   分配仅是预留；不会因此显示已联网，也不会自动替换实例地址。
2. **新建直绑实例**：选择同客户、同节点、同 profile 的未绑定直绑资源，连同选择时的编辑版本一起冻结。
   精确地址与 root pin 冻结进 `aster.node/3` 创建任务；节点成功回执确认后才显示绑定。
3. **接管已有普通网络实例**：仅支持实际停机、实际 IP/MAC 与所分配资源完全一致的接管。
   `public_adopt` 必须在节点核对实际状态、所有权、XML 和网卡；不通过替换 seed 冒充
   已有系统重新配置网络，也不支持给运行实例热换主 IP。
4. **绑定/切换浮动 IP**：选择同客户、同 VPC 的已启用非预留成员。
   新 epoch 固定全部成员和目标，经过全组 prepare → program → release 后确认。
   目标可以在另一计算节点，公网出口网关不随之猜测迁移。
5. **解绑**：直绑必须停机，节点真实 define link-down 并读回确认，留下持久墓碑；
   浮动 IP 经全组屏障撤销映射和专用 conntrack 后确认。202、网络错误和单节点 ACK 均不是解绑成功。
6. **恢复解绑**：浮动绑定出现 unknown、部分失败或批准变更时，使用独立“恢复解绑”。
   请求固定资源编辑版本和最新快照 SHA，控制器只读取得所有节点的真实 head；同事务
   新建 recovery epoch、移除本资源并冻结新编辑版本，不把旧 unknown 回执改成成功。
   保留其它资源的目标/地址/端口，仅在完整批准下接纳对应的新 root pin；最终全组放行
   才能回收。旧隐式 NAT 默认出口的 root pin 若同时变化，必须先经原网络恢复明确
   解除或转为显式地址，不能猜测新 primary 或借恢复偷偷换出口。
7. **回收**：只有不存在当前绑定、未完成任务/迁移和无法证明解除的历史引用才允许回收。
   原资源/固定操作结果保留；再次分配使用新资源 ID。不能删除旧记录来强行释放地址。

编辑使用 `expected_generation`，服务器在同一 `controller_lock` 事务校验后冻结新意图。
旧页面、新旧标签页和丢失响应不能用旧版本覆盖新绑定。资源编辑版本与虚拟机的
`DirectPublic.Generation`（迁移 incarnation）是两个不同计数器：后者只按真实来源
递增；迁移同时核对原 prepare 的冻结编辑版本和源/目标 incarnation，不用混淆字段
或回退计数解决已拒绝操作。

浏览器在发送前保存完整非秘密意图。结果不明时，只能读取原资源操作或原节点任务，
匹配 actor/action/target/请求摘要和固定结果；不能关弹窗、刷新、换 key 或读取可变
资源状态冒充原写入成功。未知状态不释放、不转绑、不自动重派。

## root 批准与部署

### 直绑

节点使用预配置、独立 routed Linux Bridge。运营者自行验证地址所有权、专用上联、
网关和管理平面隔离；本系统不改宿主默认路由、物理 NIC 或现有财务服务器网络。
目前支持同子网可用公网网关、`/1` 至 `/30` 的 IPv4 前缀；provider `/32 onlink`、
BGP/ARP 自动发布、任意多网卡/多公网地址及 IPv6 不是本合同支持范围。

先由 root 生成并审核新的精确防欺骗/特殊地址隔离 filter：

```sh
/opt/aster-cloud/bin/aster-node --print-public-network-filter aster-public-ipv4 > /root/aster-public-ipv4.xml
# 先停机并审核，不在运行中直接替换同名规则。
virsh --connect qemu:///system nwfilter-define /root/aster-public-ipv4.xml
virsh --connect qemu:///system nwfilter-dumpxml aster-public-ipv4 > /root/aster-public-ipv4.approved.xml
sha256sum /root/aster-public-ipv4.approved.xml
# 将实际输出的 SHA256 写入 Network.filter_sha256；不手编 profile 摘要。
```

该命令只输出 XML，不修改宿主。新的 filter 保留源 IP/MAC、VLAN/QinQ/IPv6 默认拒绝，
另双向阻断非公网/元数据 IPv4，ARP 仅允许精确实际网关/自身地址，
并以完整 HOST_IPS 库存阻断来宾访问本机所有接口 IPv4（含额外公网管理地址）。节点严格核对实际 filter 内容与 pin；
仅有旧 anti-spoof filter 不足以启用托管直绑。该 filter 也不是完整宿主 ACL，不能替代
专用管理平面隔离或真实上联验收。

节点完整 `network` 配置启用 `require_public_lease:true`，并设置已审核 bridge、CIDR、
网关、地址列表、DNS、filter 名称及 SHA。`DirectNetworkSHA256` 为整个 Network 配置的
摘要（含 DNS、SSH key、filter 及该开关），不是只给地址列表做 hash。
主控 root `direct_public_profiles` 必须对应其完整真实摘要：

```json
{
  "direct_public_profiles": [{
    "cluster_id": "<库存集群>", "node_id": "<批准节点>",
    "profile_id": "normal-public-ipv4", "profile_sha256": "<完整节点Network SHA256>",
    "cidr": "<公网CIDR>", "gateway_ipv4": "<公网网关>",
    "public_ipv4s": ["<批准地址>"]
  }]
}
```

示意值不是可运行配置。直绑 root 地址与所有 NAT root primary/附加地址不得重叠，
防止旧普通网络来宾与 namespace 出口抢占同一物理地址。允许批准多个节点上的同一
直绑地址以支持受控迁移，但数据库全局 active 占用仍只有一个。

`require_public_lease:true` 后，旧 `aster.node/1` 无租约公网 create/start/reboot 均拒绝；
清理、关机仍可进行。原运行实例不被强停，但停机后须经精确接管才能受控启动。
控制器的已管理节点也不会因省略资源字段退回旧 first-free 分配。

### 浮动 IP

控制器及节点对应 NAT root 均须独立开启 `allow_floating_ip:true` 和
`allow_internet_egress:true`；已有 SNAT、源网段、网关和每个 guest profile 的公网
出口批准仍必须满足。新开关默认省略且为 false，不把旧 NAT 授权扩展为公网入站授权。
修改 root 批准会改变完整 pin，须使用既有 previous-pin 显式恢复升级流程，不能直接
换配置后派发普通变更。公网地址还必须真实配置在专用 namespace outside 接口上；
只在数据库分配或 root 列表出现不够。probe 持续核验接口/路由/inode/所有权和精确规则。

## 冷迁移与回迁

普通直绑实例使用 `aster.node.storage/2`。源先确认停机，持久 source fence 并真实断开
源 NIC；签名清单带精确地址、MAC、lease、客户、root pin 和 incarnation。
目标必须有新鲜且精确的实际批准能力、相同 IP/MAC/网络审批及容量；不得静默换地址。
导入保持 inactive，目标 incarnation 为实际源 +1，单独成功 activate 后才改变运行投影。

源旧盘/域不自动销毁。独立的 `migrate_retire_source` 要求输入准确实例与制品确认、
源 root `AllowDelete`、原成功 export/fence，以及控制器通过固定 TLS 节点 **GET** 得到的
精确原 target activate 成功回执。不能由 HTTP 请求伪造 `target_active:true` 或提交自制回执。
永久退役墓碑与旧回执保留；回迁到旧节点仅允许经更高 incarnation 的新受围栏导入，
旧代任务和旧 retire 重放不能启动或删除新一代实例。

管理台目标列表来自服务端兼容判断，不把“在线”当作可迁移。源未知、目标部分导入、
root 漂移或任一未完成资源动作均阻止换新操作/回收。原 OVS VPC 的磁盘迁移仍明确拒绝旧
storage/1；浮动 IP 可在不同节点的既有 VPC 成员间移动，不等于已实现 VPC guest 磁盘热/冷迁移。

## API 增量

前缀 `/console/v1/public-ips`；原 `pools`、`leases`、`operations` 的合同不变。

| 接口 | 确认语义 |
| --- | --- |
| `GET /resources`、`GET /resources/{id}` | 当前状态及回收条件；列表支持 cluster/pool/owner/instance 过滤和 cursor |
| `POST /resources` | `{pool_id,owner_ref,mode,node_id,profile_id,vpc_id,address}`，初次 201，固定结果重放 200 |
| `POST /resources/{id}/binding` | `{instance_id,expected_generation}`，初次 202 仅接纳，重放 200 |
| `POST /resources/{id}/unbind` | `{expected_generation}`，初次 202 仅接纳，重放 200 |
| `POST /resources/{id}/recover` | `{expected_generation,expected_snapshot_sha256}`，仅恢复解绑，初次 202、重放 200 |
| `POST /resources/{id}/release` | `{expected_generation}`，确认回收 200 |
| `GET /resource-operations`、`GET /resource-operations/{id}` | 当前 actor 原操作的不可变请求/结果；不猜测当前资源证明原操作 |

实例创建使用成对的 `public_ip_resource_id`、`public_ip_expected_generation`；
资源存在时版本必填（含初始 0），两者都不选时保留旧请求原字节。

全部 POST 使用稳定 `Idempotency-Key`。新资源 ID、NAT 操作 ID、节点/实例任务 ID
不得跨表冒用。options 只投影 root 已批准地址及严格目标，不暴露配置秘密。

## 升级、备份和验收边界

- 控制器 schema **9** 新增 VM 公网资源、不可变资源操作及绑定意图；已发布 001–008
  SQL 不修改。严格核对列、索引、引擎与迁移摘要；未知/漂移不能通过忽略错误继续。
- 节点首次托管直绑后 journal 为 **5**，保留旧任务、网络绑定、source fences 和永久退役墓碑。
  旧 binary 必须拒绝未知 schema，不得删除字段/文件“降级”。旧 node/1、node/2、storage/1
  及无浮动字段的 overlay 字节兼容由测试单独锁定。
- 升级前停写，备份控制器独立库、所有节点 journals、磁盘/制品与对应配置/pin。
  回滚须匹配 binary/schema 的完整一致备份；不能仅换旧 binary、删 active 行或清空 fence。
  不恢复/修改财务库或历史订单来修复主控资源状态。
- 自动测试覆盖协议字节、精确 libvirt 替身状态、实际 MySQL 权限/事务/并发/未知围栏、
  Ubuntu22/24 隔离 namespace 浮动地址 TCP/UDP/ICMP 包流和撤旧连接、真实 API 浏览器操作。
  libvirt 替身不是实机，namespace 不是跨物理宿主或真实 Internet。
- 真 KVM、跨物理节点、真实公网/上联、宿主重启、安装升级/整机备份恢复按要求后置。
  当前不宣称完整 KVM 加强版全部功能或生产部署已验收。其余差距见
  [功能矩阵](KVM_ENHANCED_PARITY.md)，最终同提交测试记录见 [验证记录](VALIDATION.md)。

实现依据是项目自身协议与上游文档：[libvirt 网络过滤](https://www.libvirt.org/formatnwfilter.html)、
[domain NIC 配置](https://libvirt.org/formatdomain.html)、
[cloud-init network v2](https://docs.cloud-init.io/en/latest/reference/network-config-format-v2.html)、
[nftables NAT](https://wiki.iptables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_%28NAT%29)。
参考产品仅用于功能分层，不使用其 API、源码或品牌素材。
