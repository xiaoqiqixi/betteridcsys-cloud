# 主控 Console API 合同

本文件描述当前实现，不是生产验收声明。主控控制台面向 **staff 管理人员**，不是财务客户门户：Console 用户 ID 与财务 `owner_ref` 不自动相等，不共享登录，也没有隐式租户授权。不要将 staff viewer 角色直接发给财务客户。

## 1. 传输、会话与输入约束

- 浏览器入口为 `/console/v1/`，必须真实 HTTPS，Host 与配置的固定 HTTPS Origin 相符。不通过 `X-Forwarded-*` 跳过 TLS 或判断客户端 IP；没有跨域 CORS 放行。
- Cookie 为 `__Host-aster-cloud-session`，`Secure; HttpOnly; SameSite=Lax; Path=/`，无 Domain。随机 token 只有 SHA-256 hash 落库。浏览器应使用同源 cookie，不把 session token 放进 localStorage、URL 或前端日志。
- 登录前先 GET `auth/csrf`。所有写请求（包括 login/logout）必须带精确同源 `Origin` 与 `X-CSRF-Token`。登录轮换 cookie 与 CSRF token，旧会话失效；`auth/me` 可恢复当前用户及 CSRF token。
- 登录前匿名会话有效期十分钟；登录会话默认绝对有效期八小时，服务端允许配置五分钟至 24 小时，不是无限续期。禁用、密码、邮箱、角色或权限变更撤销该用户所有会话。每次请求仍从数据库读取当前 enabled 与 grants。
- 密码为 12–1024 bytes，随机 salt 的 PBKDF2-SHA256（600,000 iterations）。无默认管理员密码。首管理员由 root CLI 私密 stdin bootstrap，不能通过公开注册接口建立首管理员。
- 登录尝试按规范化邮箱十次/十五分钟、直连 peer IP 四十次/十五分钟持久限流；成功尝试也计数。未知邮箱、禁用与密码错误使用相同 `LOGIN_FAILED`。429 带 `Retry-After: 900`。
- 新匿名会话创建按规范化直连 IP 四十次/十五分钟、全局 4096 次/十五分钟限流，最多 4096 个有效匿名会话；已有有效 cookie 重用，不消耗新建额度。无效 peer IP fail-closed。不信任客户端 XFF。
- JSON 字段名严格大小写；拒绝未知字段、重复字段、错大小写别名与不允许的 null。身份 JSON 最多 16 KiB，资源 JSON 最多 64 KiB。资源请求要求声明所有非 optional 字段；下面示例中的 `confirmation` 即使无须确认也必须是空字符串，不能省略或 null。
- 身份路由不接受 query。资源写请求也不接受 query。资源 GET 仅接受对应列表明确支持的参数；重复参数、未知键与非法编码拒绝。
- 错误为 `{ "error": { "code": "..." } }`，不是自然语言错误文本。前端自行提供中英文说明，不能根据未公开的内部错误猜测成功。

## 2. 身份与账户路由

以下路径均以 `/console/v1` 开头。

| Method / path | 权限 | 输入 | 成功响应 |
| --- | --- | --- | --- |
| GET `/auth/csrf` | 可匿名 | 无 | 200 `{csrf_token}`，必要时建立短期 cookie |
| POST `/auth/login` | 匿名或已有会话；须 CSRF | `{email,password}` | 200 `{user,csrf_token}`，轮换 cookie |
| GET `/auth/me` | 已登录 | 无 | 200 `{user,csrf_token}` |
| POST `/auth/logout` | 已登录；须 CSRF | 无须 body | 204，撤销会话并清 cookie |
| GET `/roles` | 已登录 | 无 | 200 `{items:[{id,name,permissions}]}` |
| GET `/users` | `users.manage` | 可选单一 `cursor`；完整键集分页见 [成员分页](MEMBERS_PAGINATION.md) | 200 `{items:[User],limit:100,truncated_possible,next_cursor}` |
| GET `/users/{user_id}` | `users.manage` | 无 | 200 `{user}`，当前 revision |
| POST `/users` | `users.manage` 与委派规则 | `{email,name,password,role,permissions?,reason}`；稳定 key | 201 `{user,operation}` |
| PATCH `/users/{user_id}` | `users.manage` 与委派规则 | 必填 `revision,reason`，以及 `email?,name?,password?,role?,enabled?,permissions?`；稳定 key | 200 `{user,operation}` |
| POST `/users/{user_id}/revoke-sessions` | `users.manage` 与目标委派规则，含本人 | `{revision,reason}`；稳定 key | 200 `{user,operation}`；本人清 cookie |
| GET `/identity-operations/{key}` | 当前 `users.manage`、原 actor、仍可管理目标 | 无 | 200 `{operation}`；未知/外来404，不证明未执行 |

`User` 固定公开字段：`id,email,name,role,enabled,permissions,revision`。没有 password/hash、session token 或内部凭证。用户名邮箱规范化为小写 ASCII 邮箱；name 为 1–100 个 Unicode 字符。所有 user/instance/operation/artifact ID 为 32 位小写 hex；节点 ID 为 root 配置的独立标识。

固定 `admin/operator/viewer` 角色 **不传 permissions 字段**，grants 由服务端确定。新建或切入 `custom` 时必须显式传数组，可为空 `[]`；编辑已有 custom 不传该字段则保留。PATCH 至少修改一个字段；显式 null 不能充当“保留”或“清除”。

### 身份变更与回执（schema12）

账户 revision 为1…9007199254740991；写入推进一次，过期409 `REVISION_CONFLICT` 不覆盖草稿，达到上限409 `REVISION_LIMIT`。
三类身份写必须有且只有一个32位小写hex `Idempotency-Key`。已使用key409 `OPERATION_USED`，不自动重放。
理由是1–500个Unicode字符的单行文本，首尾无空格、无控制字符。密码或密码摘要不进入操作回执/审计。
`operation`绑定原actor/target/action/base/result revision、完整非秘密intent、摘要、reason、audit_id（十进制字符串）和UTC时间。
资料变更、撤销session、audit和receipt同事务；不能用当前资料相同或GET404解锁未知写。
旧前端缺少revision/reason/key会被拒绝，前后端必须成对部署；schema12回滚须恢复匹配备份。
详见[账户操作合同](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/IDENTITY_OPERATIONS.md)。应用没有receipt修改/删除接口，但现有schema级DML并非数据库强制append-only授权；逐表收敛单列W13。

### 权限与委派

| 角色 | 固定 grants |
| --- | --- |
| admin | 下述完整白名单 |
| operator | `audit.read,instances.manage,instances.read,nodes.read,storage.manage,storage.read` |
| viewer | `instances.read,nodes.read,storage.read` |
| custom | 白名单的显式子集，没有隐式管理员权限 |

完整白名单：`instances.read`、`instances.manage`、`instances.dangerous`、`storage.read`、`storage.manage`、`storage.restore`、`migration.manage`、`nodes.read`、`nodes.manage`、`users.manage`、`audit.read`、`settings.manage`。

- 非 admin 的 `users.manage` 是 **有界委派**：目标当前 grants 与拟赋予 grants 都必须是管理者自身当前 grants 的子集，且不得创建、编辑或重置任何 admin 的密码。custom 即使另持全部 grants，也不因此成为 admin。
- 最后一个 enabled admin 不能被降权或禁用；用户不能改变自身角色/grants 或禁用自身。检查在数据库事务内串行执行，不依赖 UI 隐藏按钮。
- 用户列表每页最多100条，以 `(created_at,id)` 确定性分页，`next_cursor=null` 才到末页。`settings.manage` 是权限白名单中的能力标识，**当前没有公开 settings 写接口**；节点注册、TLS pin、镜像、网络、storage 与 preset 审批仍是 root 受保护配置工作，不是浏览器任意编辑。

## 3. 只读资源 API

| Method / path | 必需权限 | 结果 |
| --- | --- | --- |
| GET `/presets` | `instances.read` | `{items:[{id,node_id,resources}]}`，root 已审批规格，不含私密节点 profile |
| GET `/instances?cursor=...` | `instances.read` | `{items:[Instance],next_cursor:string\|null}`，最多 100 |
| GET `/instances/{id}` | `instances.read` | `{instance,operations,artifacts,migrations}` |
| GET `/instances/{id}/observation` | `instances.read` | `{observation}`，实际只读节点观测；节点不可达则错误，不伪造在线 |
| GET `/instances/{id}/metrics` | `instances.read` | `{metrics}`，按需读取该实例的 libvirt 监控采样；不轮询、不计费、不更改任务 |
| GET `/operations?cursor=...&instance_id=...` | `instances.read` | `{items:[Operation],next_cursor:string\|null}`，最多 100；过滤可省略 |
| GET `/operations/{id}` | `instances.read` | `{operation}`，数据库持久化进度 |
| GET `/nodes` | `nodes.read` | `{items:[Node],next_cursor:null}`；最多 100，当前无完整节点分页 |
| GET `/audit?source=...&action=...&actor=...&target=...&from=...&until=...&cursor=...` | `audit.read` | `{items:[Audit],next_cursor:string\|null}`，固定最多 100；所有筛选可省略，资源与身份事件合并 |

资源写权限 **额外依赖 `instances.read`** 作为实例/operation 路由的基础权限；节点维护另依赖 `nodes.read`。custom 配置应明确勾选所需 read 与 write，不存在“write 自动拥有 read”的隐式推断。

### DTO 字段与分页

- `Instance`：`id,owner_ref,node_id,hostname,state,resources,created_at,updated_at`。这是持久化生命周期状态，不是持续实时遥测。旧 provisioning 的 `created` 不应被前端擅自翻译为“当前运行”。
- `resources`：`datacenter_id,compute_node_id,node_group_id,image_id,cpu_cores,memory_mib,system_disk_gib,system_storage_id,data_disk_gib,data_storage_id,network_type,bandwidth_mbps,inbound_bandwidth_mbps,transfer_gib,traffic_direction,ipv4_count,ipv6_count`。单位分别为 cores / MiB / GiB / Mbps；零带宽/流量在现有协议中是已审批 controller default，不代表无限。
- `Operation`：`id,actor_id,instance_id,node_id,action,artifact_id,target_node_id,state,created_at,updated_at`。不返回 raw task、request hash、intent hash、profile hash、协议内部 envelope 或凭证。
- `Artifact`：`id,instance_id,node_id,kind,state,created_at,updated_at`；只在 detail 且有 `storage.read` 时返回，否则 `artifacts:[]`。manifest/disk hash 不公开。
- `Migration`：`id,instance_id,source_node_id,target_node_id,phase,created_at,updated_at`；只在 detail 且有 `migration.manage` 时返回，否则 `migrations:[]`。fence、manifest、target profile 与冻结 resources 证据不公开。
- `observation`：`protocol,node_id,instance_id,owner_ref,hostname,state,ipv4,mac,observed_at,source_fenced,target_pending`。这是一次经过 mTLS、所有权与域定义验证的读；不会自动解决 uncertain operation、迁移或财务状态。
- `metrics`：独立 `aster.node.metrics/1` 合同，固定 `protocol,node_id,instance_id,owner_ref,hostname,state,observed_at,vcpus` 及下列八个 nullable 计数。主控验证 node/instance/owner/hostname/vCPU 与数据库一致，采样不超过 60 秒、未来偏差不超过 5 秒；远端读取后再次核对实例归属和放置，防止迁移中的旧节点结果被当作当前结果。
  - `cpu_time_ns`：域累计 CPU 时间，纳秒，不是 CPU 百分比。
  - `memory_rss_kib`：宿主 QEMU 驻留内存；`memory_actual_kib`：当前 balloon 分配；`memory_unused_kib`：客户机报告空闲值，可能未提供或陈旧。不据此伪造客户机内存使用率。
  - `block_read_bytes,block_write_bytes`：仅系统盘 `vda` 的累计读写字节，不含 seed 光驱或宿主其他磁盘。
  - `network_receive_bytes,network_transmit_bytes`：受管单网卡、客户机视角的累计接收/发送字节；不是已结算流量或周期用量。
  - 八个计数都为 canonical uint64 十进制**字符串或 null**，零值为 `"0"`，缺项不得用零替代；全部键必须存在。客户端须用 BigInt 等保留精度，不得先转浮点数。节点不返回宿主路径、网卡设备名或命令输出。
  - 新接口不接受 query，不支持写方法。节点 busy、未解决操作、无法确认归属/采样时拒绝；主控返回结构化错误，不回退旧数据或演示数据。网页仅点击时 GET，超 60 秒明确标记上次采样；离开实例或会话切换丢弃迟到响应。无历史采样、计费写入、自动重试或告警承诺。
- `Node`：`id,datacenter_id,maintenance,heartbeat_at,online,free_cpu,free_memory_mib,free_disk_gib,reserved_cpu,reserved_memory_mib,reserved_disk_gib`。online 仅在节点仍被 root 配置、非维护且认证心跳新鲜时为 true。free 与 reserved 是保守容量口径，不能简单视为完整可售调度器。
- `Audit`：`id,source,actor,action,target,created_at`。`source` 为 `resource` 或 `identity`；两个来源 ID 空间独立，不能只靠数字 ID 去重。不是原始宿主 journald、HTTP access log 或虚拟机控制台输出。

operation 的 `actor_id` 是不可变的意图创建者，不等于后来点击派发的人。`operation.dispatch_requested` / `operation.reconcile_requested` 分别记录实际发起者（`user:<id>`，CLI 为 `host-operator`）；`operation.dispatch_committed` 的 actor 为 `controller`，只说明 sending claim 已落盘；绑定节点回执产生的 `operation.dispatched/succeeded/rejected/uncertain` 使用 `node:<node_id>` 作为结果来源。创建者、实际请求者、controller commit 与节点结果是四种不同角色，不能互相冒名。未授权请求不能写成已授权 requested/committed 事件；requested 本身不代表节点已执行或成功。

将 `next_cursor` 当作不透明字符串，URL-encode 后原样带到下一页，不自行生成、递增或转换数值。实例按 ID 降序 keyset 分页，**不是创建时间降序**；operation 按内部单调序号，audit 按 UTC 微秒时间/source/id 稳定排序。`next_cursor:null` 表示该次列表没有下一页。detail 内 operations/artifacts/migrations 各最多 100，完整 operation 历史可另用带 instance_id 的列表翻页；artifact/migration 详情子列表暂未分页。

### 审计精确筛选

- `source` 仅为 `identity` 或 `resource`。`action` 最多 64 字节、`actor` 最多 80 字节、`target` 最多 128 字节；均须匹配 ASCII `^[A-Za-z0-9][A-Za-z0-9_.:-]*$`。**大小写、完整值精确匹配**，不 trim、不按邮箱推断用户、不支持 LIKE/前缀/通配符。合法但未出现的 action 返回空列表，不由前端擅自限制为固定枚举。
- `from` / `until` 接受带显式时区的 RFC3339，须使用 `T`，秒后最多 6 位小数，时区为 `Z` 或 `±HH:MM`（HH 00–23、MM 00–59）。规范化为 UTC 后年份须在 1000–9999；保留微秒，不静默舍入。时间范围为 **`created_at >= from AND created_at < until`**；两端都提供时必须 `from < until`。
- 多个筛选按 AND 组合；省略表示不限该项。所有参数单值；重复键、未知键、显式空值、非法时间/字符/长度、超长 cursor 或总查询串超过 4096 字节，均返回 **400 `{error:{code:"INVALID_QUERY"}}`**。不接受客户端修改 page size、排序字段或 SQL。
- 新 cursor 绑定规范化后的全部筛选；改变、增加或删除条件时必须清除 cursor，否则 400。等价的时区/小数表示规范化后可继续同一分页。cursor 最多 1024 字节，仅用于定位，不是授权凭据；权限仍逐请求从数据库校验。旧的无筛选 cursor 仅兼容无筛选请求，不得附加新条件复用。
- 前端应把 cursor 当作不透明字符串并严格 URL 编码（包括旧 cursor 中的 `~`），不要自行解码、拼接或依赖其内部格式。每个来源先按条件与 keyset 界限最多取 101 条，再进行最多 202 条的跨来源排序/合并；响应最多 100 条，没有 unbounded OFFSET 或全量导出。
- 本接口纯只读，不调用节点、不追加“查询成功”审计、不变更 operation/容量/财务。无会话 401、缺少 `audit.read` 403；新增查询不会赋予 viewer 审计权限。
- 数据库迁移 004 仅添加两张审计表各 action/actor/target + time/id 索引。部分未记账 DDL 可在精确核对已有索引后重新进入；同名错误定义拒绝，全部完成后才记录迁移 SHA。不删除历史事件，也不提供自动保留清理或防篡改外部归档；**节点 journal 与幂等/恢复记录不能当作普通日志裁剪**。

## 4. 写入、幂等与显式派发

### 网络资源管理

新增 `/console/v1/networks/{vpcs,pools,leases}` 列表、创建及 `/{id}` 原记录查询，完整字段见 [网络/IPAM API](NETWORK_API.md)。GET 需要 `nodes.read`；POST 同时需要 `nodes.read`、`nodes.manage` 和真实会话 CSRF。首建 201，同 actor/完整意图重放 200，跨 actor/类别/参数复用 ID 为 409。这里的列表按 ID 升序，游标为原样返回的小写 32-hex ID 或 null，不沿用实例/审计的 cursor 格式。

这些写入只持久化 `planned` 网络、地址池和 `reserved` 地址，**不调用节点、不把实例标记为已联网**。管理页不自动重发创建；丢失回包后保留原 ID 与完整意图，仅 GET 原记录核对。未知状态、退出/切换会话或迟到回包不能清除防重记录。地址顺序变化不产生新的地址池创建意图。没有自动释放、超时回收或未确认解绑后的重新分配。

另有 `/console/v1/overlays/` 与后台“VPC 与路由”页面，提供全局 VPC、完整成员/路由/NAT 策略、逐节点阶段任务、推进、只读核对和显式恢复，不再只留 API。读取需要 `nodes.read`；创建 VPC 另需 `nodes.manage`；epoch 写入/执行/恢复同时需 `nodes.manage` 与 `instances.manage`，并保留会话、Origin、CSRF 与审计。批准目录来自 root 安全投影，HTTP 不接收 namespace、宿主路径、命令或任意公网 IP；NAT 仅为批准前缀 SNAT/TCP/UDP 单端口 DNAT。完整接口、字段和未知结果处理见 [后台网络管理合同](NETWORK_MANAGEMENT.md) 与 [overlay 控制合同](OVERLAY_CONTROL.md)，实测边界见 [NAT 与网络管理验收记录](NAT_NETWORK_VALIDATION.md)。

以下表格继续描述既有实例操作，不能将网络资源 ID 或 epoch ID 用作 VM 操作派发 ID。

| Method / path | 输入/权限 | 成功 |
| --- | --- | --- |
| POST `/instances` | `instances.read + instances.manage`；`{hostname,owner_ref,preset_id}`；`Idempotency-Key` | 202 `{operation}`，只持久化创建意图和容量预留 |
| POST `/instances/{id}/operations` | `instances.read` 加对应 action 权限；`{action,confirmation,artifact_id?,target_node_id?}`；`Idempotency-Key` | 202 `{operation}`，不在 admission 请求里开机、复制或创建 VM |
| POST `/operations/{id}/dispatch` | `instances.read` 加已冻结 action 权限；body `{}`；`Idempotency-Key` 必须等于 path ID | 202 `{operation}`；首次明确派发，可能仍未完成 |
| POST `/operations/{id}/reconcile` | 同上；body `{}`；同 ID header | 202 `{operation}`；只读查询原结果/转运回执，不等于执行一次新的 mutation |
| POST `/nodes/{node_id}/maintenance` | `nodes.read + nodes.manage`；`{enabled:boolean}` | 200 `{maintenance:boolean}`；关闭维护仍需认证能力及新鲜心跳 |

### action 合同

| action | 额外权限 | 参数/前置状态 |
| --- | --- | --- |
| start, shutdown | `instances.manage` | 无 artifact/target；confirmation 可为空字符串 |
| reboot, force_off, delete | `instances.dangerous` | confirmation 必须精确等于 instance ID；delete 还受节点 root allow_delete 与实际关机约束 |
| snapshot_create, backup_create | `storage.manage` | 缓存须为 shutoff，节点另核验实际关机；confirmation 可为空字符串；不传 artifact/target，artifact ID 由本 operation ID 固定 |
| backup_verify | `storage.manage` | artifact_id；节点执行离线验证，实际未关机将拒绝 |
| snapshot_delete, backup_delete | `storage.manage` | artifact_id + 精确 instance confirmation；离线、所有权与状态校验 |
| snapshot_restore, backup_restore | `storage.restore` | artifact_id + 精确 confirmation；离线；保留并计入预算的旧盘，不是无证据覆盖 |
| migrate_prepare | `migration.manage` | target_node_id + 精确 confirmation；源实际关机、无 autostart、目标已审批且原子预留容量 |
| migrate_transfer | `migration.manage` | artifact_id 为 migration ID + 精确 confirmation；四阶段中的文件转运与受保护审批 |
| migrate_import | `migration.manage` | artifact_id 为 migration ID；confirmation 可为空字符串；签名/目标审批齐全，只定义离线目标，不自动启动 |
| migrate_activate | `migration.manage` | artifact_id 为 migration ID + 精确 confirmation；只有已导入且绑定一致的目标可启动 |

`create` 使用独立 POST `/instances`，不要通过普通 instance operation body 自行拼底层 create task。节点对真实域状态、root capability、磁盘与所有权的校验是最终门禁；controller 缓存上的“关机”不是绕过理由。

### 不要把 accepted 或 HTTP 202 当成成功

Operation 状态为 `accepted`、`sending`、`dispatched`、`succeeded`、`rejected`、`uncertain`：

1. accepted：意图与预留已保存，尚未发节点 mutation。
2. sending：发网络前已经持久化 claim；即使进程在此断电，也不能自动重发。
3. dispatched：节点已持久接单，仍待查询完成。
4. succeeded：对应已绑定结果确证；rejected：节点明确拒绝；uncertain：可能产生了副作用，不是“失败后重试”。

新 mutation 先生成一个随机 32-hex operation key，冻结输入并保留 key。**Admission** 的相同 key、相同 actor/意图可重放得到原 operation；不同意图或不同 actor 返回 409。主控与财务 provisioning 共用受保护 operation ID 命名空间，不允许相互覆盖。网络错误后不要生成新 key 绕过原未知状态。

**Dispatch 不得自动 POST 重试。** sending/dispatched/uncertain 只能查询原 operation 或显式 reconcile；404、网络错误、页面刷新、浏览器返回都不证明节点没执行。`reboot` ACK 不证明真正重启完成，节点可保留 uncertain。UI 应显示等待核对/人工检查，不显示绿色成功。

转运 dispatch/reconcile 在受限、可追踪的服务级后台 worker 中运行，浏览器请求返回 202，不能靠页面 HTTP 长连接保持任务。服务重启不自动恢复 mutation。普通操作也只有明确 dispatch 才发节点命令；并发节点 claim 在 SQL 中互斥，同节点其他 accepted 工作等候，不把它们送去被永久 NODE_BUSY 拒绝。

## 5. 四阶段冷迁移与流式恢复边界

1. **prepare**：源关机、验证 owned XML/磁盘与 autostart 关闭；先把永久 source fence 写入并 fsync，再导出独立 flat qcow2 与源节点签名 manifest。prepare 成功后 phase 为 prepared。失败不能自动取消已写入的 fence。
2. **transfer**：冻结源/目标 profile、owner/instance、prepare operation、manifest hash、fence、目标资源映射。主控通过固定 CIDR/CA/hostname/叶证书 pin 的 mTLS 流，将精确 manifest 与磁盘送入目标私有 inbox，验证两个文件以及受保护 approval 回执后，phase 才为 transferred。此阶段不 import、不开机。
3. **import**：目标独立验证签名、源 pin、fence、manifest/disk hash、已审批镜像与本地 network/storage；重建自己审批的 XML，不导入源 XML，不执行源提供的 URL/路径/命令。phase imported，域保持关闭。
4. **activate**：确认已导入 target binding 与原 manifest/fence，显式启动目标，查询实际 running 后才提交主控 node/resources 与 phase active。目标 compute/datacenter/group/storage 采用准备时冻结的目标映射；不修改 CPU/RAM/disk/image/network 等历史规格含义或财务快照。

### 转运安全限制

- 自动 HTTP approval 默认不开放，目标 root 必须显式启用 `AllowControllerInboxApproval`，同时审批 migration/storage、源 certificate pins 与目标镜像/网络/storage。持有 staff cookie 或提供 `source_fenced:true` 均不能替代该审批。手工 root 审查/签名交接路径仍存在。
- 源 signed metadata 最多 64 KiB；磁盘不读入全量内存，使用固定 64 KiB copy buffer。每个请求固定一次 dial、固定 endpoint，无代理、无 redirect、无 HTTP/2/pool/GetBody 隐式重放，整体最多三十分钟；节点端另有自己的执行与流超时。
- 同 transfer ID 每个文件先 GET 绑定回执；仅明确未收到的 404 才首次 PUT。existing receiving/uncertain、不同 transfer、不同 hash/文件/owner/fence 均不能重传覆盖。PUT 声明 Content-Length 与 SHA-256，目标保留 journal 与 partial 文件证据。
- approval POST 前也先 GET approval 回执。目标在签名前先持久化 approving；崩溃留下审批痕迹但未确证时返回 uncertain，不伪报“从未申请”。GET 绝不签名、创建文件、清 fence 或开 VM。
- 一旦任一 PUT/POST 响应丢失，立即保留 sending/uncertain。reconcile **只 GET**：重新读取并校验源 signed manifest，再读目标 manifest、disk 与 approval 回执。源离线也保留未知，不拼接零散目标回执冒成功。
- 如果中途只有部分文件到位或审批从未请求，reconcile 不会自动补传或补 POST。需 root 保留证据、核对或完成缺失交接后再查；这不是断点续传、自动回滚、自动容灾或无条件可恢复迁移。
- 源 API fence 永久保留，不能因目标成功、复制失败或用户布尔值解除。源清理/失效副本与旧盘、partial、inbox 的人工处置仍需 root 审查；没有宣称完整自动垃圾回收。
- 使用 storage/inbox 后节点 journal schema 升为 2。旧 binary 不认识新 fence/恢复语义，应拒绝启动；不能把旧 schema 1 journal 覆盖回去当“降级”，否则可能丢失 fence/未知操作证据。

## 6. 财务协议独立，不用 Console 写接口代替

`/v1/provisioning` 是财务服务到主控的独立机器协议，使用限定 billing Bearer token、固定 controller ID、canonical 请求 hash 与 operation/order 绑定，不使用浏览器 staff cookie。它不接收 Origin 浏览器访问。Console 不提供金额、付款、退款、订单状态或历史财务快照写 API。

财务 POST 与 GET `/v1/provisioning/{operation_id}` 的成功/可匹配重放结果是 **精确六字段、无 data/operation envelope**：

```json
{
  "protocol": "aster.controller/1",
  "operation_id": "11111111111111111111111111111111",
  "order_id": "22222222222222222222222222222222",
  "request_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
  "status": "accepted",
  "resource_id": "44444444444444444444444444444444"
}
```

这里 `status` 仅为 accepted/succeeded/rejected；controller 的内部 sending/dispatched/uncertain 不得私自扩入财务 Result。rejected 的 resource_id 为空；succeeded 必须有已绑定资源 ID。新 admission 通常 202；相同 canonical 请求重放返回 409 与原六字段 Result；不匹配冲突是 error，不能只看 409 就认定安全成功。

Staff 手工创建资源只建立主控 resource intent，**不伪造财务 order、不扣款、不把支付改成成功**。迁移只改变资源实际位置；金额精度、CNY/USD、多币种、历史快照、支付幂等与验签边界不属于 UI/Console 修改范围。

## 7. UI 与错误处理最低要求

- 401 清本地身份视图并重新登录；403 区分权限、CSRF、同源限制，不循环自动登录或重复 mutation。
- 400/415 显示输入错误；409 显示意图/状态冲突并重新 GET 原 operation；429 遵守 Retry-After；503 说明依赖不可用，保留原 operation/key 与未知状态。
- 常见 code：`AUTH_REQUIRED`、`LOGIN_FAILED`、`RATE_LIMITED`、`TLS_REQUIRED`、`ORIGIN_INVALID`、`CSRF_INVALID`、`FORBIDDEN`、`INVALID_INPUT`、`INVALID_REQUEST`、`INVALID_QUERY`、`JSON_REQUIRED`、`CONFLICT`（账户冲突）、`IDEMPOTENCY_KEY_REQUIRED`、`IDEMPOTENCY_CONFLICT`、`STATE_CONFLICT`、`NODE_NOT_READY`、`TRANSFER_WORKER_UNAVAILABLE`、`DEPENDENCY_UNAVAILABLE`、`IDENTITY_UNAVAILABLE`。同一 HTTP status 不等于同一业务状态。
- 权限控制由服务端执行；前端仍须禁用/隐藏不可操作动作、精确输入危险确认、清晰展示 pending/unknown、保留键盘焦点和可取消的 drawer/dialog。不能通过前端缓存或假成功 toast 修补后端未知结果。
- 没有 MFA、密码重置、租户自助、完整用户/子资源分页、完整 VPC 产品能力、热迁移或真实宿主验收的承诺。真实 MySQL、HTTP/mTLS fake 和浏览器回归不等于实际 KVM/guest network/跨主机/安装升级全部验收；最终证据以独立 VALIDATION 记录为准。

## VM 公网资源增量

Schema9 的直绑/浮动资源、binding_generation CAS、精确解绑回收和恢复解绑接口见
[VM 公网管理](VM_PUBLIC_IP_MANAGEMENT.md)。不扩展旧 NAT lease 结果，也不改财务
开通合同。实例创建可显式传 `public_ip_resource_id` 与选择时的 `public_ip_expected_generation`，
两者成对出现；全部省略时原创建请求字节不变；
托管节点拒绝无租约公网创建。实例新增 read-only `migration-targets` 兼容目标投影；
迁移源退役为独立 `migrate_retire_source` 确认操作，不能由前端传入自制激活证明。
