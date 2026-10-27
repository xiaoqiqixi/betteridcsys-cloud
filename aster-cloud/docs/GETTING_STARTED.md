# 主控与 KVM 被控使用入门

[主控首页](../README.md) · [安装器](../deploy/install/README.md) · [功能限制](ARCHITECTURE.md)

本文面向管理人员，说明当前管理台与主机配置的分工。它不是财务客户自助门户，也不是已完成真机验收的生产手册；真实 KVM、跨物理节点流量和宿主故障恢复仍需单独验收。

## 1. 准备两个角色

| 角色 | 放在哪里 | 安装后先核对 |
| --- | --- | --- |
| 主控 | 独立管理服务器/实例 | 固定 HTTPS 来源、专用 MySQL、首管理员、服务健康与安装回执 |
| 被控 | 专用 Ubuntu 22.04 / 24.04 amd64 计算宿主 | 真实 `/dev/kvm`、libvirt/QEMU、镜像/存储/网络预算、节点证书与维护状态 |

按[安装入口](../README.md)核验独立 Cloud Release，再使用正文中各角色的一条交互命令。预发布未公开或资产/来源不完整时停止；不要拿财务 Core 包、自动源码压缩包或开发包替代。计算节点不能部署到同时运行财务的 1GB 测试服务器。

主控可使用自带 HTTPS 服务提供网页，无需把财务 Nginx 配置复制过来。主控和财务不共库、不共享账户和 Cookie；节点也不保存财务数据库或支付凭据。

## 2. 登录管理台并分配权限

1. 打开安装向导中固定的 HTTPS 站点，例如 `https://cloud.example.com:9443/#/instances`；端口以实际配置为准。
2. 用向导设置的首管理员邮箱与私密输入的密码登录。没有通用默认密码；开发命令的首次引导也只通过私密 stdin。
3. 进入“成员与权限”（`#/users`），为每位管理人员建立独立账户；不要多人共用首管理员。
4. 按实际工作选择角色，再核对保存结果：

| 角色 | 用途与边界 |
| --- | --- |
| admin | 全部已定义管理权限，仍受业务约束、最后管理员和危险操作确认限制 |
| operator | 日常实例/存储管理和审计；不是完整系统管理员 |
| viewer | 实例、节点与存储只读；不是财务客户的租户隔离角色 |
| custom | 显式白名单子集，没有隐式权限；write 不自动包含 read |

账户编辑、停用、改密或撤会话需要原因和当前 revision；敏感变化撤销旧会话。自己撤销后应重新登录。超时后核对原身份操作回执，当前资料相同或 GET 404 不能证明这次变更没执行。详见[授权及身份 API](CONSOLE_API.md)与[账户操作合同](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/IDENTITY_OPERATIONS.md)。

## 3. 让节点可以接单

节点列表入口：**节点**（`#/nodes`）。

1. 主机管理员先按[被控运维](../NODE_README.md)审批镜像、磁盘、网络、资源预算及本机服务；按[主控运维](../deploy/controller-OPERATIONS.md)注册固定 node profile 和 preset。
2. 完成双向证书、叶证书 pin 与允许目的地址配置，核对真实已认证心跳。节点本机启动只表示 `node_started_pending_controller`，不代表主控已准入。
3. 新节点保留维护状态。核对能力、容量与实际宿主准备后，具备权限的管理员才解除维护。
4. 在节点页核对在线状态、心跳和维护结果；过期心跳、维护中或无容量的节点不应接纳新实例。

**失败时**：检查原配置、证书/SAN/pin、心跳和受限日志，不关闭 TLS 校验、不改物理上联、不清空防火墙。注册、维护切换和“在线”不等于实例可以实际联网。网页不允许任意填写节点 URL、上传宿主路径或执行命令。

## 4. 创建实例并跟踪任务

入口：**实例**（`#/instances`），只使用 root 已批准的 preset 和资源。

1. 核对节点可用，选择批准规格，填写 hostname 与明确的 owner 引用；公网资源按相应合同显式选择。
2. 提交一次创建意图，保存返回的操作 ID。`accepted` / HTTP 202 仅表示接纳，并非 VM 已运行。
3. 到“操作任务”（`#/operations`）打开原任务，按当前权限与合同明确派发；overlay 的后台 runner 有独立审批与 epoch 屏障，不能混用普通任务流程。
4. 根据同一任务的持久回执核对实际结果，再读取实例状态/观测。完成状态不证明来宾业务、SSH 或公网已可用，更不证明财务付款。

**结果不确定**：保留原任务并只读核对，不重新创建 ID、重复派发或释放预留；恢复只走明确的原任务恢复流程。操作 ID 与审计事件 ID 不是同一种编号。

电源、删除、快照、恢复与迁移在实例详情发起，各需对应权限。危险动作按界面二次确认，不能用通用状态编辑代替真实执行。快照/备份只覆盖旧普通网络合同下停止态的单系统盘；OVS 实例不能进入旧存储/迁移流程。四阶段冷迁移不是热迁移，源/目标任一侧未知时保持 fence 和占位，禁止双启动。详见[管理台 API](CONSOLE_API.md)。

## 5. 管理网络和公网 IP

入口：**网络与 IP**；先由主机管理员批准 root 网络 profile、专用桥/underlay、NAT namespace 与允许地址，再使用后台投影。页面上的库存和 planned/reserved 状态不证明真实转发或公网所有权。

| 页面 | 工作顺序 | 详细手册 |
| --- | --- | --- |
| VPC 与路由（`#/networks/overlays`） | 创建 VPC，核对批准成员/路由/NAT，冻结新 epoch，逐节点推进；未知时只读核对，必要时显式恢复 | [后台网络管理](NETWORK_MANAGEMENT.md) · [overlay 运维](../deploy/OVERLAY_OPERATIONS.md) |
| 节点网络 / IP 地址池 / 地址分配 | 建立持久网络、地址池和唯一预留，再按绑定合同用于实例；不能通过删除记录自动释放未知地址 | [IPAM 合同](NETWORK_API.md) |
| 公网 IP | 建立池、追加受控库存、分配租约、绑定 NAT 或 VM；确认全部解绑后再回收 | [公网池与回收](PUBLIC_IP_MANAGEMENT.md) · [公网 NAT](PUBLIC_NAT_EGRESS.md) |
| VM 直绑与浮动 IP | 核对 owner/VPC/节点与代次，按合同绑定、切换或解绑；直绑不热换运行主 IP | [VM 公网资源](VM_PUBLIC_IP_MANAGEMENT.md) |
| 浮动 IPv4 入站 | 明确来源网段、协议和端口；新绑定默认拒绝未允许的新入站，策略变更经过全节点屏障 | [公网入站](PUBLIC_INGRESS.md) |

这不是完整安全组：入站规则只覆盖 VPC 浮动 IPv4，不覆盖所有东西向流量或直绑实例。没有 IPv6、hairpin NAT 和自动物理上联；迁移只使用对应网络合同明确支持的路径。

## 6. 联接财务

1. 在财务商品中独立配置 preset/custom 产品参数，销售类型/地区/节点不代替主控资源 ID。
2. 主机管理员批准固定主控身份、HTTPS 目标和最小权限 token；不要把凭据写进商品或前端。
3. 仅从符合付款前置条件的原持久任务显式派发，使用原 operation ID 和不可变订单配置；核对时只读 lookup。
4. 核对财务任务和主控任务各自状态。主控不能修改订单金额、支付状态和历史快照；当前没有自动回填已开通服务的完整 worker。

Core 的资源协议最低为 0.5.10，但 `resource.aster-cloud 0.1.1` 本身仍是独立候选，不在 Core 六资产中。独立 CLI 与运行时 worker 是不同产物；按[产品配置](https://github.com/xiaoqiqixi/betteridcsys-frontend/blob/main/docs/PRODUCT_CONFIGURATION.md)、[资源插件](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RESOURCE_PLUGINS.md)及[CLI 说明](../plugins/billingconnector/README.md)选择，不混用 transport 重发未知任务。

## 7. 排障、升级与验收

- **看业务发生了什么**：审计记录（`#/audit`）按动作、操作者、目标与 UTC 时间筛选；**看进程为什么失败**：使用[运行日志](LOGGING.md)。两者都不输出秘密或任意远端错误正文。
- **遇到会话过期、403 或版本冲突**：重新认证/读取并核对权限和版本，不用旧界面缓存证明授权；未知写操作仍保留原意图。
- **升级或回退**：停写，备份独立主控库、配置/秘密、节点与 fabric journals、制品；恢复必须版本一致，不能仅换 binary 或删除迁移回执。
- **核对测试结论**：看[精确提交验证](VALIDATION.md)，区分组件、真实 MySQL、模拟节点浏览器、隔离系统/网络与真 KVM。开发测试通过不能替代物理宿主验收。

完整未完成范围见[功能矩阵](ARCHITECTURE.md)与[KVM 对照](KVM_ENHANCED_PARITY.md)。本文没有给尚未实现的 VNC、热迁移、HA、MFA 或完整客户自助界面编造操作步骤。
