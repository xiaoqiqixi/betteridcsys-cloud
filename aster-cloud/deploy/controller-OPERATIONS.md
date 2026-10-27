# 独立主控：原生部署与运行（开发版）

此程序与财务使用独立进程、独立数据库/账号、独立权限和审计。它只接收财务的不可变开通请求，不读取金额、不签收付款、不修改财务表，也不把 accepted 画成已开机。普通资源执行必须由主机操作员或具备对应权限的staff明确派发。显式批准的 overlay cluster 是独立例外：root mapping 命中的新建任务会在全组网络 epoch 确认后由后台 runner 派发，参见 [overlay 运维](OVERLAY_OPERATIONS.md)；HTTP accepted 本身仍不是 VM 已创建。节点必须另行root审批mTLS策略、image/storage/network和静态IP资源。

## 初始化与启动

首次安装优先使用[安装向导](install/README.md)，由核验后的独立 Cloud Release 提供角色命令；向导可明确准备依赖/专用数据库、安装 unit 并检查服务。下列命令描述**已准备好主机与配置的手工路径**，不代替向导，也不能直接粘贴示例跳过审批。

程序目标为原生Linux，无Docker。需MySQL8兼容InnoDB及正确UTC时间、根控制的TLS和节点mTLS文件。默认服务监听127.0.0.1:9443并强制TLS，不能由HTTP明文降级或信任X-Forwarded-Proto绕过。外部TLS终结若不能把后端TLS保留则不受支持；不要以修改Handler代替正确配置。

```
aster-controller init -config /etc/aster-controller/config.json
# init仅生成0600 root配置和三个互不相同的随机token文件，不打印token。
# 操作员填写独立MySQL DSN文件、服务器证书/私钥、已批准node profiles和presets。
aster-controller migrate -config /etc/aster-controller/config.json
aster-controller check -config /etc/aster-controller/config.json
aster-controller register-nodes -config /etc/aster-controller/config.json
aster-controller heartbeat -config /etc/aster-controller/config.json -node approved-node
aster-controller maintenance -config /etc/aster-controller/config.json -node approved-node -on=false
aster-controller serve -config /etc/aster-controller/config.json
```

根配置和secret必须绝对、规范、root所有、单链接普通文件；拒绝软链接、共享可写祖先/文件和group/world可读secret。正式加载owner始终0。测试专用owner helper不由HTTP/CLI/配置暴露。`init`不覆盖任何已有文件，部分初始化失败须操作员核对，不自动覆盖/补偿。

DSN只允许独立`aster_controller`/`aster_cloud`及其`_`前缀子命名空间；MySQL仅Unix socket或明确loopback TCP，拒绝远端明文/skip-verify/preferred TLS及multiStatements/不安全LOCAL INFILE/旧密码选项。不是在现有财务库上增加几张表。迁移为显式命令，有内容SHA256；发现不一致拒绝。创建/升级数据库用户、TLS和备份仍是主机管理员操作，程序不自动创建生产数据库。

手工路径的服务单元`controller-aster.service`仅为sandbox和资源上限模板，不由上述CLI命令自动安装/启用；安装向导另有明确批准的服务安装流程。API进程为读取root-private策略而仍以root UID运行，但capabilities清空、只读系统、无VM命令执行；不能把它说成已经完成最小权限分离。目标环境仍需验收systemd和TLS，非特权API身份/凭据交付另行实施。

## 当前 schema 12：身份操作回执

`012_identity_operations.sql` 增加用户 revision 和身份操作回执表，001–011 不修改。创建、编辑账户及撤销会话须使用当前 revision、原因和稳定操作 key；资料/会话/审计/回执在同一事务确认。前后端必须使用同一版本，旧表单缺少这些字段会被拒绝，不能只部署网页。

升级仍须停写、保留独立主控库及匹配配置/journals 的可恢复备份，以独立迁移身份显式 `migrate`，再 `check`；当前 runtime 身份仅持有本库 DML。旧 binary 拒绝新 schema；回滚需匹配备份，不删除012回执或单换旧程序。见[身份操作合同](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/IDENTITY_OPERATIONS.md)与[Console API](../docs/CONSOLE_API.md)。财务库不随之变化。

## 成员分页升级：schema 10 → 11

011 仅增加 `controller_console_users(created_at,id)` 的稳定只读索引，不修改账户、会话、权限或财务库。仍须在升级窗口按现有停写/备份流程执行显式 `migrate` 与 `check`：索引DDL提交和迁移receipt不是同一事务；重入仅承认名称、列顺序、方向、可见性、BTREE及非unique/非prefix/非expression均精确匹配的索引，不覆盖同名冲突，也不偷偷修复已记录后的漂移。

该分页增量当时将 schema 元数据推进到11；当前版本还须继续应用上面的012，不把历史11当作当前目标。不修改旧001–010，也不放宽迁移数量/SHA校验。**即使011只是索引，更旧binary仍拒绝11库**。回滚需匹配的完整主控库备份和一致journals/应用版本；不要删11 receipt、直接drop索引或单换旧binary。不要恢复财务库来代替主控回滚。

新成员前端需要新返回字段 `next_cursor`，请以同一包部署前后端。既有机器管理 `/v1/*` 的最多100条投影不因此变成完整分页；本次只改变会话管理面 `/console/v1/users`。实库/浏览器验收状态见[成员分页](../docs/MEMBERS_PAGINATION.md)。

## 根策略字段

配置包括schema=1、controller_id、listen、tls_cert_file、tls_key_file、dsn_file、billing_token_file、admin_read_token_file、admin_write_token_file、heartbeat_ttl_seconds(10–300)、nodes数组、presets数组。

node字段：id、datacenter_id、group_id、endpoint（纯HTTPS来源、不含路径/query/userinfo）、allowed_cidrs、ca_file、client_cert_file、client_key_file、server_certificate_sha256。连接同时验证CA/hostname与固定server叶证书DER SHA256；节点端另须校验controller客户端叶证书pin。DNS解析的全部地址须在允许CIDR内，单次请求固定一个地址、禁代理/重定向、禁自动重拨、POST无GetBody重放。轮换证书或endpoint改变profile SHA会阻止旧job派发/核对，须人工恢复原绑定，不能静默转送另一节点。

preset字段：id、node_id、resources（公开controllerapi.Resources全部字段），新显式VPC额外选择network_profile_id。preset以root策略固定整份资源，不随财务请求字段拼URL。custom本期要求显式具体compute_node/datacenter/group，与批准profile完全一致；不做模糊别名映射或隐含资源替换。

旧normal可执行资源形状：有实际capabilities的image/storage；normal + exact1IPv4/0IPv6，能力中必须明确`normal-static-ipv4-dedicated-bridge`；data_disk=0、data_storage空；bandwidth/inbound/transfer=0（root明确批准的节点默认），traffic_direction=all。isolated-no-nic不能冒充IPv4网络；VPC、额外磁盘、IPv6和非零带宽/流量不支持时明确拒绝，不忽略。节点还须有真实IP池、bridge、NoCloud/SSH和nwfilter策略；本期控制器不代替节点配置这些敏感资源。

### 显式单宿主 VPC（新协议切片）

旧normal/default-bandwidth路径不改。新 `aster.node/2` 仅批准显式vpc、1IPv4/0IPv6、双向各1–100000Mbps、零transfer和data disk；必须存在节点已验证的 `ovs-vpc-singlehost/1` 能力与 `ovs_network_profiles`。这不是路由VPC/公网开通承诺，也不能把旧normal同ID preset换成VPC。

完整合成配置见 `controller-ovs.example.json`：`network_profiles` 每项固定 `id,node_id,pool_id,owner_ref,profile_sha256`，可另声明 `configuration_sha256`。后者按 `(精确ProductSpec摘要,owner_ref)` 唯一选择custom商品；没有映射则拒绝，不能按地区/线路猜池。新VPC preset ID必须为 `ovs-vpc-<名称>-v<正整数>`，明确新版本且仍只批准该profile所属owner。一个SKU给多个owner使用时，各owner需独立预审批的池/profile；不是自动共享私网。

`profile_sha256` 按实际 `fabric.LoadConfig` 得到的结构计算 `sha256.Sum256(json.Marshal(config))`。这绑定node/bridge/state/root-ack等实际值；不能对有空格的配置文件直接`sha256sum`冒充它，也不能复制示例的重复字母hash。节点root配置应核对相同profile ID/hash；同一profile的绑定共享同一fabric gate。新版独立root profile不能共用不同ID的bridge/state以绕过gate互斥。

schema006将instance/create-operation/request-SHA/network-SHA和binding固定保存；租约、实例、容量、任务与审计同InnoDB事务。之后power复用原绑定，不从当今preset重建。真实激活仍由节点对root策略、IPAM binding、域/TAP和live fabric核验后执行；主控accepted不是开机许可。禁用池拒绝激活，但不禁止已绑定实例停止/删除；移除root profile会阻止所有新power写操作（含stop），停机前不要先删profile，原SHA的GET核对仍保留；未知状态不能自动释放地址。

VPC重启必须先shutdown再start，主控早期拒绝旧reboot。本切片明确拒绝VPC snapshot/backup/restore/migration进入旧storage合同；原normal路径保留。财务`aster.controller/1`、金额、支付和历史商品快照不变。schema006不能只换旧binary回滚：必须停写并恢复匹配的独立主控库备份，保留节点journal/租约和制品证据。实库CI、真实OVS/KVM、宿主重启/失败恢复和网络流量测试是不同验收层，不能相互冒充。

## HTTP合同

所有响应no-store。服务直连TLS，Bearer认证；不接受浏览器Origin/CORS，不使用Cookie。三个token须不同：billing只可访问财务桥，admin-read/admin-write仅可只读管理投影。此段只描述机器API；另有显式启用的`/console/v1`管理会话、CSRF与staff RBAC，见后文。节点endpoint/证书/preset信任根仍由root私有配置审批，网页不能任意上传或改写。

- POST `/v1/provisioning`：公开controllerapi.Request，带`Idempotency-Key`=operation_id与`X-Aster-Request-SHA256`=canonical JSON digest。新成功接纳202；完全相同重放409，返回已持久状态；不相同operation/order绑定409 `IDEMPOTENCY_CONFLICT`。全部成功/已绑定业务拒绝均直接controllerapi.Result精确6键，**无data信封**。
- GET `/v1/provisioning/{operation_id}`：相同billing token、Idempotency-Key与digest header，200当前绑定Result；未知404，不同digest409。
- 不支持配置可以持久为rejected Result（409）；无健康容量503 `NO_HEALTHY_CAPACITY`，未创建job，不假称已接单。格式错误400、缺认证401、越权403、方法405。错误仅`{error:{code}}`，不回传路径、密钥、节点诊断或SQL。
- 管理GET `/v1/health`：真实DB ping与controller/protocol；GET `/v1/nodes`、`/v1/instances`、`/v1/tasks`、`/v1/audit`：`{items,limit:100,truncated_possible:true}`。这是最多100条的只读投影，**不是完整分页、全库搜索或导出**。不泄露node endpoint、证书路径、原始request或token。
- nodes.online仅由实际已认证心跳、TTL、配置存在、非维护模式计算，不把注册或配置存在当在线。周期心跳应由操作员安装的timer执行真实GET；不自动启用监控。

## 持久性、容量和派发

独立controller_jobs/instances/reservations/nodes/audit由InnoDB事务更新。首期用singleton行锁保守串行化接纳和状态修改（吞吐有明确上限，不冒充完整调度器）；operation、order分别唯一。容量预留/instance/job/audit同事务；重放不再预留。未知/维护/过期心跳/无足够CPU内存磁盘不接纳。register-nodes默认维护且清除旧心跳，必须实际heartbeat并显式解除维护。

**容量刻意保守双扣：**心跳用总量减节点已分配与实际available的较小值，再扣全部未释放控制器预留。成功VM的预留不会因success直接释放，避免旧心跳窗口超卖；新心跳可能再次算到现有VM，从而少卖。没有实例归属证明/代际屏障前不优化掉这层扣减。只在节点明确rejected时释放；uncertain保留。现阶段不是完整库存/调度/账单配额系统。

```
aster-controller dispatch -config /etc/aster-controller/config.json -operation 32位小写hex
# 断线/超时/进程中断/写结果失败之后，只允许：
aster-controller reconcile -config /etc/aster-controller/config.json -operation 同一ID
```

`dispatch`先事务写sending和审计，再对固定节点POST已保存原始NodeTask字节+`X-Request-SHA256`。并发/重复dispatch只有一个可claim；同node有sending/dispatched/uncertain或任何未识别状态时，其他accepted订单留在主控队列，不写sending、不增加派发审计、不POST。只有前一操作明确succeeded/rejected才释放node派发槽位，不能把failed/unknown当空闲。节点先持久接单返回202 accepted，再独立bounded worker创建，不绑定HTTP取消。accepted→dispatched；节点succeeded→主控succeeded与instance.created（**不是guest SSH、业务就绪或付款证据**）。断线→uncertain，完成状态写失败则保留sending，两者都只GET核对，不POST重试；节点404也不是自动重发许可。节点rejected必须是已绑定的无效果拒绝，否则只能uncertain。已终态不允许被反向覆盖。

后台只读job为accepted/sending/dispatched/uncertain/succeeded/rejected；财务Result为accepted/succeeded/rejected，内部sending/dispatched/uncertain对财务保持accepted，不制造失败重试。精确ResourceID是控制器instance UUID，不是IP或可任意执行路径。

## 验证与未完成项

本机单元和真实TLS/mTLS测试可用`go test -race ./internal/control`。真实MySQL测试优先`ASTER_CLOUD_TEST_DSN`且库名须含`_test`；缺env明确skip。CI仅在`ASTER_MYSQL_TEST_DSN`严格指向隔离`aster_ci_test`时创建随机独立`aster_cloud_test_<hex>`并最终drop；不改生产OpenDSN限制，不读取财务表。日志不可打印DSN/token内容。

必须分别报告真实MySQL/目标Linux测试、真实KVM/静态IP/SSH、systemd安装/证书/备份恢复。模拟node RPC、contract-shaped TLS server和SQL状态测试不等于真实VM创建。本期已包含管理UI、staff RBAC、停止态快照/备份、四阶段冷迁移和查询型审计；本轮新增固定 peer 的跨节点 VPC、受控网关转发和显式恢复，范围及真机缺项见 [overlay 运维](OVERLAY_OPERATIONS.md)。仍没有MFA/租户SSO、内置 NAT/动态路由服务、完整配额告警、热迁移、自动重派、不可篡改外部归档或完整集群调度。


## 独立管理台与 staff 权限（开发版）

原机器 API 的默认启动不开放管理会话。管理台只允许固定 HTTPS Origin，浏览器不得直连节点或持有 billing / admin token。构建使用锁定依赖；以下命令在有 Go / Node 的构建机运行，不在计算宿主上安装 Node：

```sh
cd aster-cloud/frontend
npm ci --ignore-scripts
npm run typecheck && npm run format:check && npm test && npm run build
cd ..
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false -o bin/aster-controller ./cmd/aster-controller
```

将 binary 与 `frontend/dist/` 分别审核安装到 `/opt/aster-cloud/bin/`、`/opt/aster-cloud/ui/`，均 root 所有且不可被组/其他用户写入。不公开源码、配置、日志或 secrets 目录。API 保持自身 TLS；当前版本不信任转发 Header 来绕过 Origin / Host / TLS，反向代理必须保留公开 Host，后端证书应由受信链验证。

先备份独立控制器库，明确执行 `aster-controller migrate -config /etc/aster-controller/config.json`。迁移 001 不变，002 添加 staff identity，003 添加资源操作/制品/迁移表，004 添加审计精确查询索引，005 添加私有网络、IP 地址池和地址预留，006 添加不可变 instance-network 任务绑定，007 添加独立全局 VPC/epoch/成员/节点阶段表；每个 SQL SHA 被记录并核对，不允许编辑已经应用的 SQL、手工伪造版本或复用财务库。新表不是财务订单。005 会核对已有同名表的精确列/索引/引擎形状；部分 DDL 只有与预期完全一致才可重入，不采用忽略错误后手工记账。

007 确认后，只认识 001–006 的旧 binary 会拒绝该 schema，不能仅替换 binary 回退。升级须停写并备份独立主控库；回滚须恢复匹配 binary/schema 的独立库备份，并核对备份后新增的地址预留、节点 journal、制品和资源操作。不能删表、删迁移记录、释放未知地址或自动重派来“修复”版本不匹配。当前仅通过隔离实库迁移测试，整机备份还原/回滚尚未验收；既有审计增量见 [增量验收](../docs/OPERATIONS_VALIDATION.md)，网络范围见 [网络 API](../docs/NETWORK_API.md)。

首个管理员仅在空用户库由 root CLI 创建；不要把密码放进 argv、unit、shell 历史、截图或日志：

```sh
# 由受保护的本地终端/秘密管理器向 stdin 输入 >=12 字符密码
/opt/aster-cloud/bin/aster-controller bootstrap-admin \
  -config /etc/aster-controller/config.json \
  -console-origin https://cloud.example.com -email admin@example.com \
  -name 管理员 -password-stdin
```

通过 systemd drop-in 显式覆盖启动项（域名、证书与审批 build 由运营者准备，不由安装器自动信任）：

```ini
[Service]
ExecStart=
ExecStart=/opt/aster-cloud/bin/aster-controller serve -config /etc/aster-controller/config.json -console-origin https://cloud.example.com -ui-dir /opt/aster-cloud/ui
TimeoutStopSec=45
```

角色、停用、密码等变更立即撤销该用户全部会话；最后管理员和自己的角色/停用受保护。staff 是全平台运营角色，并非财务客户租户。自定义角色同时授予所需 read 权限与对应 action 权限，不能只授写权限。身份审计和资源审计在页面合并，任务详情不公开请求 JSON、证书路径、fence 或凭据。具体合同见 `docs/CONSOLE_API.md`。

### 快照、备份和四阶段冷迁移

先在节点配置审批镜像、存储、network profile 和配额。仅停止态处理磁盘，不绕过活动 qcow2 安全约束。迁移目标必须有新鲜能力心跳、足够容量和唯一明确 storage 映射。流程为 `migrate_prepare → migrate_transfer → migrate_import → migrate_activate`：每步先接纳独立、稳定操作 ID，再明确派发。202 仅表示接纳，不表示复制/导入/开机成功。

源导出先记录永久 source fence，源不能经普通 start/delete 误操作。目标转运要 root 显式开启 inbox approval 且 pin 源证书；关闭为默认。转运流不缓冲整盘、无环境代理、重定向或静默重拨，整体最多30分钟；后台最多4个转运，节点自身仍共享单执行槽。不是断点续传、热迁移或自动容灾。

丢响应后仅按原任务 ID 核对，HTTP核对入口的POST只触发**节点GET**，不会再次发原动作。若只传完部分文件而未形成审批，核对保留 unknown，须root按被控运维文档核查缺少阶段；不要创建替代任务、删除partial/fence或直接启动源/目标域。服务退出先取消转运并等待worker，恢复后不自动派发。

节点普通存储 journal 使用 schema 2、OVS 绑定使用 schema 3，新的网络恢复 completion 使用 schema 4；旧 binary 必须拒绝不认识的 schema，不得删字段降级。主控数据库新增表不能靠换旧binary完成无损回滚。回滚须停写、保留双方journals、备份独立数据库与所有制品，使用配套版本和恢复演练确认，不回退财务数据库或覆盖历史订单快照。

### 财务兼容和状态

`/v1/provisioning` 仍为原 `aster.controller/1` 的六字段结果。新 `/v1/resources/{id}` 仅billing scoped token+精确 `X-Aster-Owner-Ref` 的只读、最后确认资源投影；不是guest在线或当前任务结果。源/目标节点变化仅更新主控运行资源，绝不改原商品快照、金额、币种或支付状态。财务可继续使用既有开通合同，不强制启用新管理台或新只读接口。

### 尚未验收

管理台已有范围受限的真实HTTPS/实库浏览器记录；新页面、多浏览器和故障注入仍须另验，不沿用旧截图。真实VM/libvirt、宿主网络隔离、跨物理机磁盘恢复/迁移、原生systemd/Nginx/TLS安装和整机升级回滚均需独立验收。单测、实库、编译与流式mTLS fault测试均不能替代这些。没有用户KVM宿主前不自动安装虚拟化包，不动现有Ubuntu22财务站。

### 运行事件与审计定位

主控/被控stderr统一JSON白名单事件，独立CLI stdout保持原合同。节点未知结果或journal未确认使用WARN，绝不按日志成功自动重发。管理台支持按原任务ID查看独立详情、明确派发/核对及审计精确筛选；查询不会推进资源状态。限流、可选独立journald保留模板与恢复journal边界见 [LOGGING.md](../docs/LOGGING.md)。本轮未安装或启用这些unit模板，没有生产生命周期安装/升级/备份恢复工具；不能把手工部署说明称为已验收安装器。

## 公网 IP 库存升级

主控schema8增加公网池、append-only库存、历史租约、active占用和固定结果日志，
不改财务schema。root附加地址改变完整NAT/overlay SHA，先备份并按既有
previous pin显式恢复迁移，再使用[公网IP后台](../docs/PUBLIC_IP_MANAGEMENT.md)。
不能删库存/lease/operation表降级或仅换旧binary回滚；须兼容程序或已验证的
完整一致性备份恢复。旧未知节点任务必须保留，真实宿主验收仍后置。

## 虚拟机公网资源升级（schema9）

009 在 schema8 库存之上新增直绑/浮动资源、单调编辑版本与不可变绑定意图；
原 NAT lease 和历史操作结果不变。节点直绑需要 journal5、精确新 filter/root pin
和 `require_public_lease:true`，浮动 IP 需要独立 `allow_floating_ip:true`。
先停写备份主控独立库、节点 journals/fences/磁盘制品，再按
[VM 公网管理](../docs/VM_PUBLIC_IP_MANAGEMENT.md) 审批配置和升级，不能由 HTTP 扩权。
冷迁移源退役是单独确认动作，不自动删源盘；源未知/目标部分完成时不回收地址。
旧 binary 不认识 schema9/journal5；禁止删新表/绑定/墓碑或清空 active 回滚。
真实公网、KVM 和整机恢复验收仍须专用宿主完成，不动现有财务服务器网络。
