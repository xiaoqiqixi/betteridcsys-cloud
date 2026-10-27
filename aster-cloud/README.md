# 星屿云 · 云主控与 KVM 被控

独立的云资源管理系统。财务负责销售和账务，主控管理资源任务，被控在计算宿主机上通过 libvirt / QEMU / KVM 管理虚拟机；客户虚拟机内无需安装被控。

**[使用入门](docs/GETTING_STARTED.md) · [安装器](deploy/install/README.md) · [功能矩阵](docs/ARCHITECTURE.md) · [管理台 API](docs/CONSOLE_API.md) · [更新记录](CHANGELOG.md)**

当前为开发系统，**真实 KVM、物理网络和完整生产部署尚未验收**。预发布通道独立于财务 Core，不包含在财务六资产中，也不意味着稳定生产版。Go + MySQL + Vue 3 / TypeScript，原生 systemd；支持目标为 **Ubuntu 22.04 / 24.04 amd64**，暂不支持 Ubuntu 26.04。

2026-10-27已完成首个RC的正式构建、独立签名和公开下载/只读plan复验；具体源码、资产与未验范围见[公开交付记录](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/CLOUD_PUBLIC_ACCEPTANCE.md)。运行命令仍以固定Release正文为准，不复制可变main脚本代替发行入口。

## 可以做什么

| 模块 | 当前实现 | 使用限制 |
| --- | --- | --- |
| 管理台与权限 | 登录、admin/operator/viewer/custom、成员管理、撤销会话、任务和审计 | 不是财务客户 SSO；没有 MFA 或受控 VNC |
| 实例与节点 | 审批 preset 创建、电源/删除、节点维护、持久任务和只读实时样本 | 真实资源依赖已批准且健康的节点；采样不是历史监控或计费账本 |
| 快照、备份与迁移 | 旧普通网络实例的停止态单系统盘快照/备份、四阶段冷迁移 | OVS 实例拒绝旧存储/迁移合同；没有热迁移、HA 或定时异地备份 |
| VPC、OVS 与路由 | IPAM、不可变实例绑定、启停门禁、固定 VXLAN peer、跨节点 epoch、批准路由与显式恢复 | 须预备专用桥、underlay 与 root profile；没有完整子网/DHCP/IPv6/租户安全组 |
| NAT 与公网 IP | SNAT、TCP/UDP DNAT、公网 IPv4 出站、地址池/分配回收、普通网络直绑与 VPC 浮动 IP | 库存不证明上游路由和地址所有权；不热换运行实例主 IP；不支持 IPv6/hairpin NAT |
| 浮动 IP 入站 | 实例独立 IPv4 来源/协议/端口规则，新绑定默认拒绝未经允许的新入站 | 仅覆盖 VPC 浮动 IPv4 入口，不是完整安全组；旧映射须明确升级 |

完整限制、协议和后续目标见[功能矩阵](docs/ARCHITECTURE.md)与 [KVM 功能对照](docs/KVM_ENHANCED_PARITY.md)。上表是代码范围，不是实际客户资源可用承诺。

## 安装：主控与被控各一条命令

1. 查看独立 [Cloud Release](https://github.com/xiaoqiqixi/betteridcsys/releases/tag/cloud-v0.1.0-rc.1)。**仅在该版本实际公开、完整资产与来源核验成功时，使用正文中对应角色的单条命令**；不可下载时不能换成本地包冒充正式通道。
2. 主控向导采集自己的域名/TLS、专用 MySQL 与首管理员信息；被控向导采集计算宿主与节点策略。
3. 审查只读 plan，明确批准依赖、配置、apply 与 start。密码私密输入，不放进命令行或日志。
4. 按[使用入门](docs/GETTING_STARTED.md)核对管理站点、节点准入与权限，再开展隔离环境验收。

初始 HTTPS bootstrap 固定完整源码 SHA，需操作者信任并审核该入口；后续包与相邻安装器代码核验固定 GitHub Actions / Sigstore 身份、精确源码、哈希和清单，不读取用户 token。任一来源或清单不符即停止，不回退开发包。详见[下载信任链](docs/RELEASE_CHANNEL.md)。

### 两种安装角色

- **主控**：可显式准备固定 Ubuntu 依赖与新的专用 MySQL，或使用已审查的本机独立数据库；runtime DML 与迁移 DDL 身份分离。自带 HTTPS 服务和网页，不要求另装 Nginx；不会自动修改 DNS、防火墙或申请证书。严格 HTTPS/数据库/首管理员/服务检查通过才报告 `service-ready`。
- **KVM 被控**：可明确批准准备官方 libvirt/QEMU 完整软件栈；约束 vendor 服务/socket 自动启动并核验真实隔离状态，不修改物理上联、netplan、防火墙或已有 VM。外来活动 libvirt 不接管、不重启。启动须有真实 `/dev/kvm`、证书、批准镜像与预算；初始维护开启，网络和删除默认关闭。本机 `node_started_pending_controller` 不是主控已准入。

安装器要求受支持 Ubuntu、Python 3.10+ 和真实 systemd。Ubuntu 22/24 的签名隔离来宾测试验证真实 APT/systemd/libvirt 准备，**不等于 KVM、物理网络、宿主故障恢复或生产验收**。不能把同时运行财务的 1GB 服务器当计算节点。

详细输入、结果与恢复见[安装器手册](deploy/install/README.md)、[包合同](docs/INSTALL_PACKAGES.md)、[安装验证](docs/INSTALL_VALIDATION.md)。本地开发包只走明确 development 授权与独立可信 SHA，不可代替正式下载校验。

## 使用与运维

- **第一次操作**：[登录、节点准入、实例与任务](docs/GETTING_STARTED.md)。
- **主机配置**：[主控运维](deploy/controller-OPERATIONS.md) · [被控运维](NODE_README.md) · [术语](GLOSSARY.md)。
- **网络**：[后台 VPC/路由/恢复](docs/NETWORK_MANAGEMENT.md) · [公网池与分配回收](docs/PUBLIC_IP_MANAGEMENT.md) · [公网 NAT](docs/PUBLIC_NAT_EGRESS.md) · [直绑/浮动 IP](docs/VM_PUBLIC_IP_MANAGEMENT.md) · [公网入站规则](docs/PUBLIC_INGRESS.md)。
- **故障定位**：[日志与审计](docs/LOGGING.md) · [overlay 运维](deploy/OVERLAY_OPERATIONS.md) · [恢复合同](docs/OVERLAY_DESIGN.md)。

所有写任务先持久化意图。结果不明时保留原 ID 并只读核对，不自动重发开通、释放地址或清空 journal。节点只执行预定义动作与 root 批准资源，不接受任意 shell、XML、宿主路径或下载 URL。主控服务当前仍使用受限 root UID，不把 systemd sandbox 说成已完成非特权 API 拆分。

## 财务适配

财务和主控使用独立数据库、身份与权限，不共享客户会话。主控不能改账单、确认支付或读取财务库；商品销售分类与实际计算资源 ID 分开管理。

- 财务 `aster.resource/1` 的最低版本为 Core **0.5.10**，上界 `<0.6.0`；Core 已有正式发行，旧正式 0.5.9 不含此协议。
- `resource.aster-cloud 0.1.1` 是**独立资源 worker 候选**，不是 Core 六资产之一；构建、核验、选择与启用见[资源插件](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RESOURCE_PLUGINS.md)。Core、plugin-host、plugin-manager 必须来自支持协议的同一经核验版本；安装插件不启动资源服务，不证明 VM 已开通。
- 独立 `aster-billing-plugin` CLI 使用 `aster.controller/1`，`runtime_plugin=false`，不是上述 worker。见[适配器说明](plugins/billingconnector/README.md)与[财务产品配置](https://github.com/xiaoqiqixi/betteridcsys-frontend/blob/main/docs/PRODUCT_CONFIGURATION.md)。

## 数据与升级

- **主控 MySQL：schema 12**。012 增加成员 revision 与同事务身份操作回执；001–011 不改，财务 schema 不随之升级。
- **节点 journal：最高 schema 5**；**fabric journal：最高 schema 3**。新绑定、所有权墓碑和归档链不能删除或被旧程序忽略。
- 历史 64 次 fabric 变更上限已移除，使用 32 条活动页及不可变 SHA 链归档；仍有容量与历史核验成本，不是无限存储。

升级前停写，完整备份主控库、journals、配置/秘密与制品。回滚须恢复匹配的一致版本，不能只换旧 binary、删表/receipt/journal 或释放未知地址。账户升级见[主控运维](deploy/controller-OPERATIONS.md)及[身份操作合同](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/IDENTITY_OPERATIONS.md)。

## 开发与验证

在开发机运行，不安装服务、不修改宿主网络或创建虚拟机：

```sh
cd aster-cloud
export GOTOOLCHAIN=go1.27.3
GOCACHE=/tmp/aster-cloud-go-cache go test ./...
GOCACHE=/tmp/aster-cloud-go-cache go vet ./...

cd frontend
npm ci --ignore-scripts
npm run format:check
npm run typecheck
npm test
npm run build
```

CI 使用 Go 1.27.3、Node.js 24.19.0；无测试 DSN 会跳过实库场景，不能算 MySQL 验收。完整门禁须在隔离环境运行，不能指向生产库。API 开发见[Console 合同](docs/CONSOLE_API.md)、[网络 API](docs/NETWORK_API.md)和[overlay 合同](docs/OVERLAY_CONTROL.md)。

测试结果、源码 SHA、实际截图与明确跳过项集中在[验证记录](docs/VALIDATION.md)，不在首页重复历史数量。代码只更新 `main`；独立 Cloud 标签不覆盖财务旧标签、资产或 `latest`。真实 KVM 与物理网络按计划后置，不能标记为已通过。
