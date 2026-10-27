# 独立主控 / KVM 被控变更记录

本文件记录 `aster-cloud/` 的 main 开发增量，不代表独立主控已发布正式版本或完成生产验收。
财务 Core 与 SMTP 的版本、资产和历史记录另见[财务变更记录](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/CHANGELOG.md)
与[Core v0.5.10 发行记录](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RELEASE-v0.5.10.md)；主控开发目录不附加到财务发行资产。

## Unreleased · main 开发中

当前开发增量与历史已验源码分开记账，不把尚未提交的工作区或旧 CI 结果写成新的验收终点。
功能存在、任务接纳、节点确认和真实环境验收是不同事实；完整支持范围见
[功能与验收矩阵](docs/ARCHITECTURE.md)。

### 2026-10-27 · 文档导航与当前版本校正

- 项目首页改为产品能力、安装/使用入口和开发导航；新增文档中心、财务首次使用与主控入门，技术证据保留在独立验证/历史记录中。
- 当前主控 schema 为12，修正文档遗漏身份操作迁移的问题；当前顶部导航与旧侧栏说明分开，不沿用旧截图结论。
- 最低财务 Core 0.5.10 已有正式发行；资源 worker 0.1.1 仍是独立候选，不在 Core 六资产中，CLI 与 runtime worker 不混称。
- 增加文档入口、本地链接、源码路由/引导字段、迁移版本和过期兼容措辞回归；不改财务金额、支付、历史快照、SQL 或运行时代码。精确执行结果见[27日记录](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/EXECUTION-20261027.md)。

### 2026-10-26 · W07-B 账户修订、会话撤销与原操作核对

- 新Cloud迁移012：用户revision及同事务唯一身份回执。旧版本409拒绝覆盖，缺key/revision/reason拒绝；已用key不重放密码操作。旧001–011及财务SQL不改。
- 编辑前读取最新版本；撤销目标全部会话含当前设备，撤销前在途登录也须锁内复核代次。本人撤销离开认证界面，不停止VM或取消任务。
- 身份未知结果使用独立1MiB完整公开意图账本；GET原actor/target/intent对应回执才清理，404/当前资料/VM任务不能冒充证明。密码不入持久存储或审计。
- 集成Gemini App原创的连续ledger表单、反馈与确认层，修正Unicode码点、固定角色只读、唯一ID及Vue scoped深色选择器；嵌套层仅最上层接焦点/Back。
- 保留205成员只读、原70张图及全部网络门，另增独立实库身份有限写验收。1620cdc实际28检查/10图和Cloud11门成功，但财务倒计时测试失败未记全绿；人工看图再补入场过渡/实际视口，现29检查/10图待新同SHA运行。
- 修复刷新后的遗留弹窗标记、结果反馈滚入当前层与Teleport确认主题继承。本地完整前端1001项、扩展Go/MySQL/race2538 PASS事件；macOS四项native明确跳过。当前发行必需集合加入Ubuntu22财务门，共16门，结果逐SHA另记，详见[执行记录](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/EXECUTION-20261026.md)。MFA/SSO、逐表DB授权和真实KVM并未随本包完成。

### 2026-10-26 · W07-B1 排队身份写入的会话边界

- 账号创建/修改在identity事务锁内锁定原已认证会话，重新确认owner/有效期；注销、改密或到期后的排队请求完整401拒绝且不写账户/审计。
- 缺少内部会话证明不能直接调用写入口；证明仅hash/subject，不将原Cookie带入公开DTO、日志或任务。注销与账户更新锁序统一。
- 既有授权、有界委派、最后管理员与审计事务保持；双管理员HTTP竞态要求一成功、一401，另一有效设备和新登录仍可管理。
- 无新SQL/公开接口/UI入口，不改财务金额、支付、历史快照；revision、全部会话撤销与身份未知结果回执仍待后续切片。结果及环境限制见[实施续记](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/EXECUTION-20261026.md)。

### 2026-10-25 · W07-A 主控成员完整分页（4626e32同SHA实库验收通过）

- `/console/v1/users` 支持严格单一 cursor，按 UTC 微秒时间+ID 稳定读取100条及1条前瞻；明确下一页或末页，兼容标记不再固定为true。
- 成员页提供上一页/下一页、真实页内数量；失败不推进页栈，401/403与身份变化清旧数据及抽屉，迟到响应不能跨账号回写。不增加搜索/导出或虚假总人数。
- 当前主控 schema11 仅新增 `(created_at,id)` 索引；精确定义校验，允许正确DDL未写receipt重入，拒绝冲突/已记录结构漂移。001–010 SQL及财务数据库不改。
- 旧 binary 仍严格拒绝11库；回滚需匹配的主控库备份/一致恢复，不能删除receipt或只换旧程序。前后端响应合同须配套部署。
- RED→GREEN、本地结果与未验项见[成员分页](docs/MEMBERS_PAGINATION.md)；未将本地缺DSN的SKIP算作MySQL或浏览器验收。
- 4626e32已实际通过Cloud11门与财务4门；成员205人三页、18项浏览器检查及6图包含在原网络门内，详见[10月26日续记](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/EXECUTION-20261026.md)。不是正式发行或真KVM验收。

### 2026-10-25 · 网络操作意图与真实财务浏览器门禁

- overlay新请求先验证完整持久意图，再写存储及发送；不再让坏payload污染后续无法读取的账本。发送使用已冻结的body。
- overlay与三类公网IP/入站策略账本均拒绝空串损坏，读前/写前限制1MiB UTF-8原始数据；保留128条、owner/权限/匹配约束，不截断或淘汰未知意图。
- 浏览器配额写失败不发送POST；未知回执保留原key，确认清理失败仍保留待核实记录。
- Cloud发布门禁新增同精确SHA的独立真实MySQL财务浏览器job；该job缺失、跳过、失败或被演示检查替换均拒绝，不能只凭15这个数量放行。

### 2026-10-25 · 财务资源 worker 的最低Core兼容声明

- worker候选升为0.1.1，避免旧main本地0.1.0产物修改manifest后产生同版不同哈希；不覆盖旧目录，不放宽安装校验。
- 主控侧统一声明 `resource.aster-cloud` 0.1.1 / `aster.resource/1` 最低Core为0.5.10，当时为未发布候选（27日Core发行另记，worker仍独立候选）；旧正式0.5.9不具备资源协议，不再借用旧main版本号声称兼容。
- 与独立 `aster-billing-plugin` CLI 明确区分；CLI仍是 `runtime_plugin=false`、原 `aster.controller/1` 动作和结果合同，不添加新的付款/金额操作。
- 财务侧协议常量、插件构建清单和管理器由财务模块同步；不更改现有金额、支付、历史快照，不推送或发布。

### 2026-10-25 · M0：当前支持范围收敛到 Ubuntu22/24

- 按用户确认，当前只支持 Ubuntu22.04/24.04 amd64；Ubuntu26 暂缓，不把旧失败改称通过。
- 安装 apply/provision、libvirt 计划、TCG 固定镜像/CLI/C sandbox、必需 CI 与 Release 文案一致收敛；26/未知目标拒绝。
- 普通离线包 plan 仍能检查包，但不支持目标明确返回 `unsupported-no-apply`，不能据此执行安装。
- 保留旧26准备记录，不删除宿主核心包保护、网络隔离、真实KVM检查或来源验签。当前15项发布前检查（Cloud11+财务4，包含独立真实MySQL财务浏览器）须由新精确提交重新通过。
- 此范围收敛已在4626e32通过22/24真实TCG与GitHub门禁；正式下载和真机仍待验，不把TCG软件准备称作KVM，见[续记](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/EXECUTION-20261026.md)。

### 2026-10-25 · 原生 libvirt 准备与独立预发布通道

- 主控 / 被控继续使用独立角色的一条交互命令，新增固定提交 bootstrap、匿名官方资产下载和离线 Sigstore 复验。
  仅允许 `cloud-v0.1.0-rc.1` 预发布；固定 workflow / 仓库 ID / 源码 SHA / 完整资产清单，认证安装器所有相邻代码后才执行。
  release ID 是 GitHub HTTPS 元数据，不冒充 build 签名；本地 receipt 不因写着 verified 就取得授权。
- 被控可显式准备官方 libvirt 完整软件栈，包安装期间禁止自动启动 vendor 服务与 sockets，保留 AppArmor / QEMU 用户策略。
  专属 Unix-only daemon 使用空网络目录只读挂载视图；包脚本可生成默认 XML，但不得激活默认 NAT / bridge。
  已有活动 libvirt 只读核验，未知 / 部分状态不覆盖。丢启动回执只停止本次拥有的服务，不清理未知 VM / 网络。
- 新增 Ubuntu 22.04 / 24.04 / 26.04 官方镜像验签、TCG 隔离 guest 的真实 APT / systemd / libvirt 门禁。
  固定 image SHA，禁 host mount / host forwarding；独立核验宿主网络未变、无默认网络、无 TCP libvirt，真实 doctor 继续拒绝无 KVM。
  这不是 KVM 真机、虚拟机业务或生产升级恢复验收；通过与否以精确 SHA 的 CI 为准。
- 发布流程分离 build / attest / publish 权限，要求同提交既有财务、实库、浏览器及新增 native checks；构建两次比对字节。
  只创建新 Cloud prerelease，不改旧标签、旧资产或财务 latest。发布后两个角色须实际匿名下载、验签并执行生产只读 plan。
- 本轮不修改财务源码、金额、支付、币种、历史快照，也不修改 Cloud 业务 Go 代码或数据库迁移。
  [发布合同](docs/RELEASE_CHANNEL.md)与[验证记录](docs/VALIDATION.md)分别记录机制、已执行结果和未验项目。

### 2026-10-25 · 一体化管理工作台

- 去掉桌面旧侧栏与重复 topbar，改用单条 52px 导航。手机保留当前入口、语言与外观、导航菜单；身份与退出放在抽屉内，避免挤占小屏。
- 将 Gemini 的独立导航与实例清单设计拆为纯视图组件，接回原有会话、权限、API 与稳定操作意图；未采用原型中的计时假成功、假指标或新造业务协议。
- 实例桌面表格与手机连续清单均保留规格、节点和状态；完整 ID 可展开、复制，浏览器拒绝复制时提供手动方式。任务受理、派发与待核实不改称完成。
- 节点、网络/IP、任务、审计、成员与详情使用统一语义色和连续资源分组；原自定义选择器、焦点约束、浏览器返回及未知写入保护继续保留。没有加入货币、订单或支付模块。
- 公网 IP 小屏标题动作占满一行，保留按钮换行能力与 44px 目标；浏览器门禁新增 390/320px 实际满行、对齐与单行文本检查，待精确提交 CI 实测。本地完整前端现为 **37 文件 / 892 tests** 通过。
- 合成 DTO 的本地视觉检查与真实 API 验收分开记录；当前提交的真实 MySQL、严格 TLS 浏览器和历史数据不变性门禁由 GitHub Actions 执行，不沿用旧 UI 的通过结论。

### 2026-10-25 · 历史阶段：独立开发包与原生安装向导

- 新增独立主控与 KVM 被控本地开发包合同、manifest / 外部 SHA256 校验和两条角色向导入口。
  默认只读 plan，apply 需要 root、目标系统与真实审批；拒绝不安全归档、路径别名、覆盖现有配置/秘密和
  未经原审批增加宿主副作用的 resume。版本 staging、私密回执与失败停步不等于生产部署验收。
- 主控沿用原生 HTTPS 静态 UI 与现有 init/check/migrate/bootstrap 接口；可显式选装固定官方 Ubuntu
  依赖并创建新专用 MySQL。长期 runtime DML 与迁移 DDL 身份/配置分离，不借用或升级财务数据库；迁移专用 DB 级
  `REFERENCES` 覆盖 002 的真实外键创建，runtime 仍无 DDL/REFERENCES 权限。
  只有新建专用 MySQL 使用 socket-only drop-in，既有 DB/用户/服务或 policy 不覆盖；口令不输出到日志/argv。
- 节点只可选装固定 qemu / virsh-client / cloud-localds 工具。完整 libvirt daemon 的默认网络自动化
  未开放，干净节点端到端一键部署仍未完成。不改物理上联、桥接或防火墙，不创建假镜像；维护开启、
  网络与删除关闭。节点本机启动仅为 `node_started_pending_controller`，controller 私钥不导入节点。
- 当前本地安全测试：独立 installer **93**、专属 unit **10**、packager **23**，均通过；shell/语法/
  diff 检查通过。测试使用合成制品与宿主命令替身，不是实际 APT/MySQL/systemd/KVM 验收。
- `59367c2` 的两个 Linux unit job 因测试夹具读取真实 runner 的 fresh-host 证据而失败。
  本轮仅隔离夹具并独立补齐真实守卫回归，生产限制不变；后续精确提交的 CI 结果仍须重验。
- 独立正式 Release / 官方下载通道仍缺失，财务 `v0.5.9` 资产不变。真实本地开发包只执行过校验与
  plan/dry-run，未远程部署。新 UI 的实库与浏览器门禁独立执行，不由开发包 plan/dry-run 推定。
  入口与限制见[项目说明](README.md#原生安装主控与被控各一条命令)和[当前验证](docs/VALIDATION.md#当前工作区开发安装器安全测试)。

### 2026-10-25 · 响应式导航与长页修复

对应 `f58c4bd..66e2d49` 的四次提交：`db05fe9`、`c5ca3d4`、`302141c`、`66e2d49`。

- **中小屏使用抽屉**：在 `<=1024` CSS px 使用现有导航抽屉，工作区占满可用宽度；
  `>1024` CSS px 保留桌面侧栏，避免 721–1024px 的侧栏挤压内容。
- **长页与短屏分开处理**：桌面侧栏背景随文档延伸，导航面板保持视口高度并 sticky；
  短屏内仅导航列表独立滚动，品牌、账号和退出按钮可达，不靠滚动整个业务页面露出菜单。
- **完整键盘目标可见**：显式排除滚动容器的额外 Tab 停靠；聚焦导航链接时显示完整点击区域
  与焦点留白，而不只显示文字。真实 Firefox 捕获的短屏裁切问题纳入回归。
- **跨断点与关闭清理**：抽屉支持焦点约束、Escape、遮罩与浏览器返回；路由、身份和
  1024/1025px 断点变化正确清理 history、背景 `inert` 与滚动锁，并把焦点移到可见目标。
- **跳到主要内容**：可见 skip link 聚焦主内容，但不覆盖 hash-router 的当前路由。
- 该历史导航修复轮次只修改前端 shell、测试、浏览器验收脚本与设计说明；没有修改主控/被控/财务生产后端、
  schema、依赖或 workflow。既有创建实例测试改为等待真实 WebCrypto 完成，仍要求原完整请求且仅一次 POST。

### 2026-10-24 · 公网地址与独立入站规则

- **公网出口**：在 root 独立批准下，支持 IPv4 Internet 出站，不再要求逐个批准公网目的前缀；
  原明确路由和 DNAT 仍可保留。管理网、metadata、underlay、保留网段与反欺骗限制不因公网模式放宽。
  见[公网 NAT 出口](docs/PUBLIC_NAT_EGRESS.md)。
- **公网池与库存**：支持池创建、追加地址、启停分配、精确/自动分配与确认回收；
  NAT 租约、VM 公网资源及保守历史占用共同参与全局唯一占用判断。禁用池不抹除现有绑定，
  未完成任务或不能证明已解除的历史引用不得回收。见[公网 IP 管理](docs/PUBLIC_IP_MANAGEMENT.md)。
- **直绑与浮动 IP 分层**：普通网络新建实例可将批准的单个 IPv4 冻结进 `aster.node/3`；
  已有普通网络实例仅支持实际停机且 IP/MAC 完全匹配的接管，不提供运行中热换主 IP。
  浮动 IP 是同客户、同 VPC 既有成员间的独立地址资源，支持绑定、跨节点成员切换、解绑与恢复解绑，
  不等于移动 guest 磁盘。普通直绑冷迁移保留地址并使用源围栏与显式源退役。
  见[VM 公网管理](docs/VM_PUBLIC_IP_MANAGEMENT.md)。
- **绑定不等于放行**：VPC 实例经浮动 IPv4 的公网入站规则与地址资源分离。新绑定冻结目标实例的
  策略版本；空规则默认拒绝未经允许的新入站，合法主动出站回包保留。支持来源 IPv4 CIDR、
  TCP/UDP 端口区间与 ICMP echo；IP 移动不会带走原实例的规则。
- **生效与就绪不混用**：策略、资源 generation、网络 epoch、固定操作结果和审计同事务绑定；
  全节点 prepare → program → release 精确回执完成后才确认生效。当前 root pin/授权漂移、
  心跳过期或能力撤回会使读取结果转为待核实，不用旧回执冒充当前就绪。
- **兼容与未知结果**：旧省略 ingress 的映射保留原 legacy 字节并明确提示，不静默标为安全；
  新绑定不能通过 `null` 降级为旧全端口语义。响应丢失仅核对原操作完整意图，不能换 key 重发、
  读取可变资源猜成功或清空 unknown。范围仅为浮动 IPv4 公网入口，不是完整安全组、IPv6
  或普通直绑接口防火墙。见[公网入站规则](docs/PUBLIC_INGRESS.md)。
- 该历史切片的独立主控数据库为 **schema 10**：008 公网池/库存、009 VM 公网资源、010 实例入站策略；
  旧迁移与历史请求/快照/回执不重写。升级须停写并完整备份主控库和相关 journals，
  不能只换旧 binary、删表或删除 journal 回滚。财务数据库不随之迁移。

### 历史精确源码验证：`66e2d49`

以下结果只绑定上述 `66e2d49`，不作为新提交、正式发行或真实 KVM 的验收结论：

| 检查 | 实际结果与范围 |
| --- | --- |
| 前端 | format、typecheck、production build 通过；32 文件 / 845 项测试。 |
| 独立真实 MySQL | 483 个顶级测试、2006 个子测试通过，0 FAIL / SKIP；两类计数不相加宣传独立场景。 |
| Linux Firefox + 真实 HTTPS / MySQL | 162 项业务检查 + 51 项 shell 检查，共 213 项；64 PNG（原 52 张业务图 + 12 张 shell 图）。节点 RPC 为明确测试替身。 |
| 布局与键盘 | 320/390/768/1024/1025/1440 CSS px 长页；1440×360、1025×360 短屏完整目标；中文浅色与英文深色。720×450、512×384 为缩放等效 CSS 视口，不是真实浏览器 200% 缩放。 |
| CI | [cloud CI 40118438918](https://github.com/xiaoqiqixi/betteridcsys/actions/runs/40118438918) 与[财务 CI 40118438913](https://github.com/xiaoqiqixi/betteridcsys/actions/runs/40118438913) 的 12 项必需任务最终全部成功。Ubuntu22/24 原生 NAT 包流只覆盖隔离 namespace，不等于真实公网或 KVM 包流。 |

独立 MySQL job 首次在环境准备耗时 **21m53s** 后触及 **25 分钟**总时限，测试未完成，
不计为通过；只重跑同一 SHA 的该 job 后完成实库与扫描门禁，没有放宽 timeout 或删除测试。
64 张截图不代表逐张人工认证；本轮人工复核选取其中 6 张。原业务 workflow 保持
13 个 epoch、78 次唯一 overlay 节点 POST 和 3 次直绑节点 POST，原历史字节保留。
浏览器和证据规则见[网络浏览器门禁](deploy/ci/NETWORK_BROWSER.md)，分轮记录见
[独立验证记录](docs/VALIDATION.md)。

### 仍后置的验收

真实 libvirt/KVM guest、跨物理宿主 OVS/VXLAN、实际公网地址/上联、宿主重启与故障恢复、
整机安装/升级/灾备仍待独立验收。没有验证真实手机硬件或实际浏览器 200% 缩放。
本轮不宣称完整 KVM 加强版、完整安全组、生产可用或可直接销售，也不改变财务金额、
币种、支付幂等和历史财务快照。
