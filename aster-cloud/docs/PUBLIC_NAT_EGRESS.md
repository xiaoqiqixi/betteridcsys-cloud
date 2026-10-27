# 公网 IPv4 NAT 出口

本轮在 main `71df3aaab18755c84b1d4f70130f840132f604da` 之上增加真正的
Internet 出站模式，不再要求把每个公网目的地址加入前缀白名单。
金额、支付、历史订单、财务资源请求、原 `aster.node/2` 创建绑定和旧网络
快照 / 回执不修改。只更新 main，不创建标签或替换既有 Release。

后续公网池、分配回收及实际出口地址选择已接入，详见
[公网 IP 管理](PUBLIC_IP_MANAGEMENT.md)。本文保留公网出站模式本身的合同与历史记录。

## 管理员操作

进入“网络与 IP → VPC 与路由 → 配置网络”：

1. 选择对应 VPC 的网关与 NAT 配置；界面显示批准的出口 IPv4。
2. 打开“出站地址转换”，将“出口范围”选为“公网 IPv4”。
3. 如只需公网，指定路由可留空，端口映射可全部删除；空数组不是默认路由。
   如需保留独立批准的路由 / DNAT，可与公网模式并存，其旧限制不放宽。
4. 勾选公网确认并输入集群名称，提交一个新网络版本。节点仍按
   隔离与准备 → 应用配置 → 确认并放行执行，`202` 不等于已生效。
5. 关闭“出站地址转换”会同时关闭公网，或切回“仅指定网段”；原网络版本
   和回执仍可查看。删除 NAT 会关闭其全部转换，不会忘记受控 namespace。
6. 响应丢失只核对原 ID，不重复下发未知任务；恢复会新建版本，公网恢复
   同样需要确认。关闭、替换或恢复会中断已有 NAT 连接以确保撤销生效。

读取继续要求 `nodes.read`，规划 / 执行 / 恢复同时要求 `nodes.manage` 与
`instances.manage`，并使用真实 TLS 会话、CSRF / Origin、CAS、审计事务与
持久未知意图围栏。不开放“上传宿主命令 / 网卡路径”的后台能力。

## 上联、地址与独立 root 批准

公网地址必须是运营方实际持有且上游已路由的地址。地址格式通过不等于
地址所有权、上游连通或出口已可销售；不要使用测试中的虚构公网地址。
节点仍使用 [专用 namespace/veth/路由/归属合同](../internal/fabric/NAT.md)，
不抢占 SSH / 财务网卡，不改宿主默认路由、宿主 nftables 或宿主 forwarding。
专用 outside peer 的物理上联由宿主运营方预配置，不从 HTTP 自动搭建。

在 NAT 所在节点的私有 `nat_profiles[]` 中设置：

```json
{
  "allow_snat": true,
  "allow_internet_egress": true,
  "public_ipv4": "<实际获分配的公网 IPv4>",
  "uplink_gateway_ipv4": "<专用上联下一跳>"
}
```

以上仅列新增 / 相关字段，不是完整有效配置。`allow_internet_egress` 默认
关闭；开启时要求 SNAT 批准及真正公网源地址。private / CGNAT / link-local /
loopback / 文档 / 测试 / multicast / reserved 地址不能伪称公网出口。
控制器相应安全投影也要设置 `allow_internet_egress: true`、相同公网 IP 和
实际 NAT profile SHA；不向浏览器暴露 namespace 路径或 inode/device。

**每个参与节点**另用 `guest_networks[]` 明确批准公网数据平面与初始 guest
默认路由，包括 NAT 在远端、甚至该节点暂时没有本地 VM 的情况：

```json
{
  "local_vpc_id": "11111111111111111111111111111111",
  "vpc_id": "22222222222222222222222222222222",
  "owner_ref": "33333333333333333333333333333333",
  "cidr": "10.11.0.0/24",
  "gateway_ipv4": "10.11.0.1",
  "allowed_prefixes": [],
  "allow_internet_egress": true,
  "dns_ipv4": ["1.1.1.1", "8.8.8.8"]
}
```

替换 ID、owner、CIDR 和 DNS 为实际值。公网批准必须绑定精确全局 `vpc_id`、
owner、CIDR、网关；相同地址空间不能借用另一 VPC 的批准。本地成员还必须
匹配其原 `local_vpc_id`。DNS 为可选、有顺序、最多四个独立地址，不做自动
探测或默认外部 DNS；要由 guest 自动解析域名，应显式配置可达解析器。
DNS 必须是已批准前缀可达地址，或公网模式下的有效公网地址。

新建 guest 的 cloud-init seed 才写入 root 批准的 `0.0.0.0/0` 路由和可选
DNS。这是 guest 路由准备，不是启用 NAT：后台关闭公网时数据平面仍拒绝。
**旧 guest 的 seed 和磁盘不重写**；原来没有默认路由的 guest，需由其运营方
在系统内明确配置默认路由 / DNS 后才能实际出站，后台不能靠重启伪称已更新。
本轮没有新增自动登录 guest、执行 guest 命令或改变原创建快照的通道。

新增批准改变完整 root SHA；已有部署必须沿用完整 overlay 与 NAT owner 的
`previous_profile_sha256` 和显式恢复迁移，不能静默更换 pin 或删除 journal。
每个参与节点的 root 批准仍是独立执行边界，控制器管理员不能只靠公网 flag
越过它。关闭 / 缺省所有新字段时旧 root / snapshot canonical 字节保持不变。

## 转发及隔离

- 公网通路允许已启用冻结成员发起 TCP、UDP 和 ICMP echo。TCP/UDP/echo
  返回必须属于已建立的 SNAT 连接；相关 ICMP 仅允许类型 3/11/12 的
  conntrack-related 错误，包含公网路径的 PMTU 错误。不存在任意入站放行。
- 公网通路排除 IANA 特殊用途网段（含 RFC1918、CGNAT、文档、link-local）、
  管理保护前缀、全部节点 underlay IP、全部 VPC 及本节点批准 NAT 的
  public/uplink 自身地址。`protected_cidrs` 应覆盖所有实际管理网络，含
  使用公网地址的管理网。非公网源 ICMP 错误同样拒绝，不宣称其可穿透。
- 旧的明确批准前缀 / DNAT 保留优先权；其权限本来就单独由 root 审批，
  不会因为打开公网扩大来源、端口或目标。纯公网且无指定路由不允许凭空
  添加 DNAT 来源。IPv6、hairpin、公网 IP 分配与 NAT HA 不在此实现。
- OVS 仍严格匹配源 MAC/IP、端口、VNI、固定 VXLAN peer、受控下一跳，
  不学习 / flood / NORMAL / 远端转发远端。公网路径是低优先级独立路径，
  特殊地址 drop 高于默认公网路径，原精确批准规则优先级不变。实例 ingress /
  egress meters 保留。nft 普通链共享排除表，不对每成员复制全部保护网段。
- namespace FD 钉扎、原子 nft JSON、完整规则 readback、conntrack 撤销、
  VM 创建 / 启停的实时核验和失败隔离沿用。规则漂移不被旧成功回执掩盖。

## 本轮验证入口与诚实边界

- 协议测试：显式 true 独立摘要、false/缺省旧字节、严格 JSON、一般 `[]`
  不隐式开放公网、`null` 拒绝。root 审批测试额外覆盖每节点独立 / 精确 VPC
  以及 guest seed/DNS 不改变原绑定、不覆盖既有 seed。
- 控制器策略和真实 MySQL：公网启停、空路由、省略保留 / 显式清空、丢 ACK、
  恢复、审批撤回零突变、审计失败回滚、TLS/RBAC/CSRF、财务/node 字节不变。
- 前端组件：出口范围 / 公网 IP、SNAT 联动、原/替换恢复确认、未知意图精确
  GET、dirty 关闭、键盘及小屏；真实浏览器由严格 TLS + MySQL 门禁另外验证。
- Ubuntu22/24 的 `TestNativeNATInternetEgressAndRevocation`：仅在三个独立
  namespace/veth 中构造公网格式的合成地址，实际 TCP/UDP/ICMP 出站回包及
  SNAT、私网/元数据/underlay 拒绝、未请求入站拒绝、program 阶段隔离、
  禁用后已有 TCP 失效、宿主 nft 规则不变。公网目标不在任何批准目的前缀。
- 实库浏览器必须完成五个 epoch、两个 VPC、30 个唯一节点 POST，并验证
  纯公网启停、旧快照和回执不变。节点 RPC 是明确的测试替身，不是真 VM。

上述是可重复门禁，**脚本存在、语法通过、本地假 runner 通过都不算实际
Linux/实库/浏览器已通过**。本轮执行记录及 GitHub 同提交结果另保存在
`artifacts/public-nat-20261024/`，不能套用前轮 71df3aa 的绿色构建。

首轮 `ec2f765` 的实际 Ubuntu22/24 nft 输出揭示三类表示差异：`/32` 输出
为单地址、ICMP payload 自带协议依赖而省略冗余 meta、组合 ct state 输出为
`[2,8]`。已将真实 1.0.2 / 1.0.9 输出加入测试，修正 compiler 直接生成该
canonical 表示；**未放宽 normalizeNFT**，移除任一 ct / SNAT / 地址隔离 /
普通链 / ICMP 协议仍必须失败。该轮新增 MySQL 用例全部通过，但新原生入口
未分流导致其 no-skip 门禁失败；分流名单现仅增加这个精确 native 测试名，
对应 Ubuntu22/24 专用任务都必须实际 PASS，不能容忍任何 MySQL skip。
修复后的最终提交仍需重新执行全部门禁，不能把原始 JSON fixture 当作包流通过。

随后原生 TCP/UDP 与严格规则读回已通过，ICMP 确实收到 echo 回包，但测试
helper 的 `IPConn.Read` 把 IPv4 头当作 ICMP 头而失败；改用标准库
`ReadFromIP` 剥头，并额外严格核对源地址、完整 ICMP checksum/type/code/
id/sequence/payload。真实捕获报文及错误 / 截断负例纳入纯 Go 回归；没有
修改生产转发规则，也不把未知 ICMP、网络错误或超时当成成功。

真实 KVM/libvirt、跨物理节点流量、实际公网地址 / 上联连通、宿主故障恢复、
HA 与生产部署验收仍按要求后置；CI 隔离包流不等于已做这些真机验收。

参考：[IANA IPv4 特殊用途表](https://www.iana.org/assignments/iana-ipv4-special-registry)、
[nftables NAT](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT))、
[OVS actions](https://docs.openvswitch.org/en/latest/ref/ovs-actions.7/)。本轮实际读取，
不是安装第三方控制器或照搬其代码。
