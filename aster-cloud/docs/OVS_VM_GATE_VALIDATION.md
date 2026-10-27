# OVS 实例门禁与财务资源插件验证（2026-10-23）

本次 main 开发变更把 OVS 接入主控 admission、被控 VM 创建/启动和停止路径，
不是只增加 `aster-network` 命令。**尚未完成路由或跨节点 VPC；不宣称完整
KVM 加强版或可供真实客户生产使用。** 用户延期的是真实 KVM 验收，不是测试。

## 已接通的链路

1. 主控 schema 6 新增不可变实例网络绑定；与 instance、IPAM lease、capacity、
   task 和 audit 使用同一 `controller_lock` 事务。pool/owner/node/VPC 必须一致。
   新 VPC preset 使用独立 `ovs-vpc-...-vN` ID；custom 产品同时按冻结产品摘要和
   owner 选择 root profile。不重写已售 preset、金额、付款或历史产品快照。
2. 新 `aster.node/2` 严格绑定 16 个 scalar 网络字段；原 `aster.node/1` wire bytes
   和正常网络能力保留。财务原 8 字段请求及 SHA 不变；仅独立 node request 扩展。
   后续 power 复用最初 binding，不能因今天改套餐而换地址/限速/bridge。
3. 节点在创建/启动使用固定 OVS virtualport、TAP、domain UUID 和 network digest。
   初始 persistent NIC link-down；fabric 排他锁跨过 drop、paused bootstrap、
   动态 TAP/ofport 身份核验、flow/meter apply/readback、link-up/resume 和最终持久化。
   运行中 start 只核验；停机后 start 新走门禁，不把历史 applied 回执当启动许可。
4. shutdown/force_off/delete 先隔离并确认 TAP 消失，再删除旧端口 allow。
   故障保留 uncertain，拒绝自动重发；必要时额外尝试有界、已验 ownership 的
   link-down/suspend，不强制删除/重启。不能把安全隔离命令 ACK 当作隔离成功。
5. schema 3 节点 journal / schema 2 fabric journal 拒绝旧二进制降级；旧 power-only
   Reconcile、OVS 直接 reboot、旧 snapshot/backup/restore/migration 合同均拒绝，
   不允许从旧入口绕过门禁。停机重启需显式 shutdown 再 start。
6. 财务独立 `resource` 插件 slot 接入既有持久化 job 的主机派发命令；manager→
   launcher→非 root worker→固定批准的主控 HTTPS，默认旧 HTTPS 路径不变，
   resource 失败不 fallback。详见 [资源插件](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RESOURCE_PLUGINS.md)
   及其[实际 Linux 测试记录](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RESOURCE_PLUGIN_VALIDATION.md)。

## 实际运行的检查

以下均在本次修改后执行，不拿此前 main 结果充数。PASS 数区分测试事件和 package。

| 环境/入口 | 结果与证据范围 |
| --- | --- |
| macOS Go 1.27.3，全 cloud `go test -mod=readonly -race -count=1 -timeout=10m -json ./...` | 1372 test PASS，220 个顶层 PASS，12 package PASS，0 FAIL；26 test SKIP，见下文。测试使用受控 runner，不运行实际 KVM/OVS。 |
| 节点/协议定向 race | 459 test PASS，0 SKIP/FAIL，覆盖严格 wire、创建/启动/停止、旧协议、失败重启不重放、漂移和 reconcile 拒绝。此计数属于上面全量检查的子集，不相加。 |
| libvirt v8.0.0 官方 RelaxNG | 生产 `domainXML` 实际导出后经 `xmllint --nonet --relaxng` 通过；错误 virtualport/link-state 两负控均拒绝。仅 XML 语法，没有执行 virsh/KVM。 |
| `go vet ./...` 与 Linux amd64 static build | controller/node/network/billing-plugin 全通过。交叉编译不是 Ubuntu 部署认证。 |
| `govulncheck v1.9.0`，Go 1.27.3 | 官方漏洞数据库在线扫描，没有发现适用漏洞。 |
| 管理台 | typecheck、format、545 tests、production build 通过；在线 `npm audit --audit-level=high` 0 漏洞。无本轮 UI 变更或新浏览器截图声明。 |
| Ubuntu 22.04 独立原生 MySQL 8.4.13 | 新增网络 admission 的 4 顶层 + 5 子测试全部通过，0 SKIP/FAIL；Linux 非 race 二进制，不冒充 Linux race。 |
| Ubuntu 22.04 资源插件 | runtime 112、host 9、bridge 3 PASS 事件；manager 51 tests OK；实际 worker 包通过生产 manager verify。详细 scope/非 race/未启动服务见独立资源记录。 |

### 实库覆盖与清理

新 4 个顶层覆盖：财务原 request/SHA 不变与冻结 power binding；staff create；
错 owner、禁用池、审计失败、binding INSERT 失败的整个事务回滚；并发 IP 分配与
耗尽；租约/绑定漂移阻断；schema 6 重入和错误 view/列/唯一约束冲突。

测试不连接财务库。用已存在原生 MySQL binary 启动独立 nobody 实例，私有 Unix
socket、禁 TCP、MemoryMax 256MiB、32MiB buffer；测试账号只获本轮随机库前缀权限。
测试期间未读取原 MySQL 凭据。结束临时用户/库数量为 0，独立服务 inactive，测试
目录和凭据目录删除，cgroup OOM 为 0，原 API、edge、MySQL 全部 active。

### 明确跳过项

本机没有 MySQL DSN，跳过控制器/IPAM/身份模块实库入口（含身份的 10 个子例）；
另有一个需 root-owned TLS 文件的 connector 测试未在 macOS 普通用户下执行。
合计 **26 test skip events**。新增 4 个网络实库顶层已在上述隔离 Ubuntu22 实际运行，
但这不替代全套 Linux race、旧财务 native/systemd/backup/rollback 和完整 MySQL CI。
最终 GitHub workflow 仍须按最终提交单独核验，不能用此局部记录宣布 CI 已绿。

### 保留的失败与修正

- 初次全量 macOS sandbox 禁止 httptest 监听回环地址，出现 `bind: operation not
  permitted`。没有删 TLS 测试；按权限流程允许隔离回环监听后原样重跑全量通过。
- 独立审查发现 libvirt 8 的 `domif-getlink/setlink` **没有 `--live` 选项**；修正为
  active-domain 默认语义并保持 paused/running 核验，fixture 同步拒绝错误选项。
  依据[官方 libvirt8 getlink 源码](https://github.com/libvirt/libvirt/blob/v8.0.0/tools/virsh-domain-monitor.c#L704)
  和[setlink 源码](https://github.com/libvirt/libvirt/blob/v8.0.0/tools/virsh-domain.c#L2884)。
- 旧 reconcile 仅查 running，可能把 release ACK 丢失后的未知网络误报成功，已拒绝
  OVS 走此旧入口并增加回归。metrics 只认 `vnet*` 的旧逻辑也已精确支持本实例固定
  `ast*` TAP，不允许任意同前缀接口。
- 首次真实 MySQL 的 schema 冲突用例因 VIEW 的 engine/collation 为 NULL，Scan
  先报错导致分类为 unavailable。改成 NullString 后显式拒绝错误 table kind；
  保留初次失败、精确修复单例和最终 4 顶层通过记录，没有降低 schema 校验。

非敏感证据在忽略目录 `artifacts/ovs-admission-20261023/` 与
`artifacts/controller-network-20261023-89fe755c94c1/`，包含 JSONL、计数和 cleanup；
原始测试 stdout 中只有合成 fixture。不要提交测试凭据或把这些本机构建叫 Release。

## 剩余阻塞，不能标“已完成”

- **路由、跨节点 VPC、VXLAN、NAT/浮动 IP、DHCP、IPv6** 尚未实现。本轮只有
  同宿主 private IPv4 peer isolation 与双向 drop meter，不是排队整形。
  [OVERLAY_DESIGN](OVERLAY_DESIGN.md) 只是下一条完整协议/执行链的设计，不是功能。
- fabric 当前每专用桥累计最多 64 次变更，达到即 fail-closed（包括 guarded stop）。
  生产前必须实现保留重放身份的安全 journal 归档/压缩与故障恢复；禁止删 journal
  续次数。OVS 不确定状态的专用安全 reconcile 和存储/迁移绑定合同也未补齐。
- 尚无真实 KVM/OVS 双租户抓包、吞吐、spoofing、ofport 重用、重启和故障恢复验收；
  Ubuntu22/24 的真机行为仍未认证。没有连接用户财务宿主的物理网卡来冒充网络验收。
- 新 resource systemd service 的实际 credentials/sandbox 部署及真实订单派发未验收；
  显式 host job dispatch 不等于自动开通调度器。主控不进入现财务 Release。

本次仅更新 main；不改已有标签、不发布未经上述验收的完整云平台 Release。
