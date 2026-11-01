# 迁移验证服务的隔离进程

## 用途与边界

`verificationprocess` 将已有的受限 HTTPS/SQL 验证服务放进独立的 Linux 非 root 进程。
它不是普通主控启动器，不创建 `App`、资源执行器、心跳或节点连接，也不解除目标封存。

当前为实现中的内部调用链：已接控制器私有子进程入口、原安装归档批准、专用系统账号和
受管安装中的固定 root 运行入口和 systemd 启动/状态/停止；已添加 Ubuntu22/24 真实已安装 ELF/管理器场景，新增链路仍待原生验收。
**快捷安装器的用户引导、专用系统账号/root/systemd 链路的原生验收、原恢复账户的浏览器登录、
停止后的完整数据阶段与账号撤销串联仍待接入。** 不提供可绕过这些前置条件的用户启动命令。
`8fa0566` 的 Ubuntu22/24 配置恢复场景已通过：严格 TLS、受保护静态页、非 root 线程、
隔离网络空间全部 IPv4 路由表为空，以及停止、到期、父死亡后的真实进程和 SQL 排空。
[该提交 CI](https://github.com/xiaoqiqixi/betteridcsys-cloud/actions/runs/41282985998) 为 18/18 通过，
两平台产物已核对下载大小、SHA256、源码及场景字段。此前 `47b24c9` 的路由格式误判已修复。
此证据不含后续原安装批准通道和专用系统账号，不能把它继承为这些新增调用链的验收结果。

另有[独立只读页面的真实浏览器检查](../../aster-cloud/docs/BROWSER_VALIDATION.md#迁移验证模式的独立浏览器检查)，
使用生产受限处理器和真实最低权限 SQL，但不经过这里的 root/子进程启动链。
其桌面/手机截图和登录成功不能替代本节原生进程验收，也不能提前放行完整迁移。

## 原安装批准到受限服务

`RunTargetVerification` 不接收归档路径、DSN、UI 路径或外部成功报告。它重新读取原操作，
核对当前执行文件就是该受管版本中的控制器，再认证原归档与目标 plan。在
`PrepareVerificationRuntime` 的同一个控制锁内验证原数据阶段、已发布配置和保存的最小 SQL 凭据，
然后向 root 管理器提交新派生的公开核验内容；不能再嵌套另一层封存锁，也不延长原截止时间。

内部 `migration-verification-coordinator` 命令只认固定继承的匿名 Unix 通道和真实 root 父进程。
通道使用一次性 nonce 和当前核验消息的 SHA256 绑定回应；不接纳旧报告、未知字段、额外消息、
任意命令或密码参数。root 管理器必须持有安装/目标锁，再检查完整 SQL 对象及账户清单、安装字节
和专用系统身份，才能批准 UID/GID。通道关闭、额外字节、父进程退出或停止信号均取消接纳。
这是固定受管 root 入口的内部通道，不代替完整的 systemd 协调器。

取得父子独立 guard 后，仍须等待归档回调结束、明文暂存销毁成功，才调用隔离服务。
清理失败不启动 HTTP，守卫保留至专用 root 协调进程真实退出。子进程只收到最小 SQL 凭据、
已验证 TLS、配置元数据和该安装固定的 `ui/`；不读取恢复密钥、迁移 SQL 凭据、财务 token 或节点私钥。

新增原生场景通过实际安装控制器执行这条链：错误核验摘要拒绝、完整 root SQL/清单再核验、
严格 TLS 页面与 401、明文目录已消失、并发重复启动被忙锁拒绝、通道关闭后真实退出，
并重新核对原阶段与封存。`verification_original_approval_launch` 为必需证据，缺失不能算通过。
该场景改用固定安装入口准备的专用系统账号，检查实际子进程每个线程的 UID/GID、附加组和权限。
新增账号场景仍待自身源码原生执行，不宣称 systemd、原账户登录或完整迁移通过。

## 专用系统账号

`target-verification-system-prepare` 与只读的 `target-verification-system-status` 只接收原操作 ID。
它们重新走受管安装、原归档/封存/数据阶段、最小 SQL 凭据和完整 root 数据库清单核验；
不允许传入用户名、数字身份、shell、路径或修复开关，不启动 HTTP，也不解除封存。

- 名称由原操作派生，UID/GID 由系统在 100–999 范围内分配，不使用测试身份 65532。
- 固定 `useradd --system` 创建密码锁定（shadow 为 `!`）、`nologin`、无家目录、无附加组的身份；
  不设置账号到期，不修改已有账号。这是运行进程的 Linux 身份，与客户账号、服务器订购期限无关。
  迁移验证 HTTP 仍受原计划的绝对截止时间限制，不会因系统身份不设到期而延长。
- 当前支持本地 `files` / `files systemd` 的身份源；LDAP、SSSD、非完整清单等会明确拒绝，
  不把远端身份查询失败当作名字或 UID 尚未使用。
- 同时核对 NSS 的按名称/数字查询、完整用户和组清单、shadow/gshadow、附加组及真实进程身份。
  UID/GID 共享、可登录 shell、成员/权限增加或未知进程一律拒绝。
- root 私有开始记录绑定原计划、原数据阶段与随机所有权标记；完成记录绑定四类账号记录摘要。
  不输出 shadow 内容，不自动解锁、改组、改 shell、删除或接管外来身份。
- 显式再次准备时，只有四类本地记录都明确不存在，才允许用原开始记录继续一次创建；
  部分存在或属性漂移不重建、不修复。已完成记录必须逐字保持，状态查询不会产生写入。

原生测试新增外来同名组拒绝、实际账号创建与重复核验、账号 shell 漂移拒绝且不修复、
原私有回应下发实际身份，以及运行中线程身份与停止后空闲状态核对。
`verification_dedicated_system_identity` 是配置恢复必需证据；本机格式/CLI 测试不能代替它。
独立低层进程测试仍使用 UID/GID 65532，二者证据范围不混用。当前不自动删除已完成操作的账号；
它保持密码锁定、禁止登录、无目录，后续受管清理需另验真实进程与 SQL 撤销后再执行。

Linux 22/24 单元任务在长测试之前增加真实 `useradd`/NSS 快速核验，调用同一套固定创建和检查函数，
检查无到期、密码锁定、无登录 shell、数字身份隔离、外来身份拒绝、属性漂移不修复与本次身份清理。
它不启动 HTTP、不连接 MySQL，不代表安装后的原计划批准链通过；完整安装场景仍单独验收。
证据只导出固定布尔值及源码 SHA，不输出 shadow、随机所有权标记或原始系统记录。

账户命令行为参照 Ubuntu [22.04 useradd](https://manpages.ubuntu.com/manpages/jammy/man8/useradd.8.html)、
[24.04 useradd](https://manpages.ubuntu.com/manpages/noble/man8/useradd.8.html) 和
[getent](https://manpages.ubuntu.com/manpages/jammy/man1/getent.1.html)；仍以本项目实际原生报告为验收依据。

## 固定 root 运行入口

已安装的 `controller-migration.py target-verification-serve --operation <原操作 ID>`
是前台阻塞的受管验证入口，不是普通主控启动或已发布的一键迁移命令。它不接受路径、UID/GID、
凭据、成功报告、期限或任意程序参数，不自动创建系统账号，不启动业务执行器。

1. 重新验证完整安装字节、目标封存、原归档/数据阶段、SQL 清单与已完成专用账号；
   安装锁及目标锁一直持有到实际退出后的检查结束。
2. 只启动该安装的 Go 私有协调器。收到新的在途核验消息后再次检查完整 SQL 清单、安装清单、
   原批准及系统身份，再以本次 nonce、完整消息摘要与实际 UID/GID 回应，不采用之前打印的 JSON 票据。
3. 只认可原绝对期限；管理器保留一次计算的单调时钟剩余时长，不能以时钟回退、重启或重试续期。
   TERM/INT 先关闭私有通道；对自身真实子进程有界等待，失败后才终止并等待，不读取 PID 文件杀进程。
4. 返回前复查无主控进程、安装字节、原不可变数据阶段及允许的认证差异、系统账号空闲，
   并从完整 MySQL 连接清单确认活跃及未认证连接均为零。到期后用数据状态核对，不尝试续期开机。
   返回只表示停止核对，保持 `service_started=false`、`migration_ready=false`，不当作浏览器就绪。

原生场景新增**实际执行该安装 Python 入口**后的严格 TLS、重复入口忙锁拒绝、TERM 后真实退出与
数据/连接核对，以及杀死自己启动的 root 父进程后，按内核 PID/启动时间观察后代真实退出。
此部分不由 fixture 代发批准消息；新增必需证据 `verification_installed_root_manager`。
本机 CLI、语法和报告门禁通过，不等于该 Linux/root 正例已通过；不在开发 Mac 上启动此入口。

## systemd 生命周期

同一安装入口新增三个只接受原操作 ID 的动作：

| 动作 | 行为 | 不代表 |
| --- | --- | --- |
| `target-verification-start` | 重做完整启动前核验，准备该操作的运行期 unit，然后请求启动固定 root 入口 | HTTP 就绪、账户登录成功或迁移完成 |
| `target-verification-service-status` | 只读核对 unit 字节、有效设置、实际进程和 cgroup，报告 systemd 状态 | 当前业务数据完整核验或浏览器验收 |
| `target-verification-stop` | 只停止核实属于该操作的 unit，再查 cgroup、原阶段、系统身份和完整 SQL 连接清单 | 撤销账户、目标激活或源主机恢复 |

unit 固定为 `/run/systemd/system/aster-target-verification-<操作>.service`，只执行当前安装的 Python
管理器；不接收 unit 名称、PID、程序、凭据或强制开关。它没有 `[Install]`，不启用开机启动，
`Restart=no`，`KillMode=mixed`，`NoNewPrivileges=yes`。TERM 先让管理器关闭私有通道并等待；
主进程已退出仍有后代，或停止达到 120 秒时，由 systemd 对剩余 cgroup 进程收尾。
3700 秒运行上限只是兜底，不能延长父子独立执行的原批准期限。
`Type=exec` 仅确认启动了程序；返回保持 `http_readiness_verified=false`、`migration_ready=false`。

运行期私有回执绑定 boot ID、原操作/阶段、安装 manifest、专用账号回执和带随机标记的 unit 字节。
外来同名文件、其他验证 unit、drop-in、重启/停止程序/权限改写、未知 PID 或 cgroup 均拒绝，
不覆盖、不接管、不用 PID 文件杀进程。`systemd-analyze verify` 先解析 unit，才重载并请求启动。
安装/目标锁在启动请求前释放，真正服务重新取得锁并重新批准；独立操作锁串行化 start/status/stop，
避免管理器等待自己仍持有的锁。停止后的只读数据核对支持原期限已到达，不伪造新的凭据认证。

原生场景增加外来 unit 拒绝、实际 systemd 严格 TLS、停止与连接排空、状态只读、已停止 unit 漂移拒绝
且不修复、显式同操作重新核验后启动，以及杀死自己启动的管理器后不自动重启。
`verification_systemd_lifecycle` 是必需证据。**新增场景尚未取得自身源码 Ubuntu22/24 原生结果**；
本机只执行 CLI、unit 格式/有效属性及报告门禁，未在 Mac 创建服务。
运行期回执和已停止 unit 暂时保留；完整迁移后的 unit/系统身份退役与账户撤销仍需串联验收。

设计参照 Ubuntu22 的 [systemd-run](https://manpages.ubuntu.com/manpages/jammy/man1/systemd-run.1.html)
中对 exec 就绪边界的说明和 [执行环境](https://manpages.ubuntu.com/manpages/jammy/man5/systemd.exec.5.html)，
以及 [停止过程](https://manpages.ubuntu.com/manpages/jammy/man5/systemd.kill.5.html)。
实现使用固定运行期 unit，而不是接收自由命令的通用执行器。

## 父进程职责

调用 `Serve` 前必须完成原归档、安装来源、目标封存、原不可变数据阶段、完整账号清单、
保存的最小权限 SQL 凭据、TLS 和专用 UID/GID 的核验。整个明文清理步骤必须已成功返回。
只能传入 `PrepareVerificationRuntime` 给出的独立子进程 guard；父进程的原始独立 guard
持续至协调进程实际退出。不能将一个预检查 JSON 当运行批准。

父进程只执行同一个受保护的 ELF，固定私有命令，不从参数选择其他程序。它在专属锁定
OS 线程上先设置不可恢复的 `no_new_privs`，再创建非 root、无附加组、独立网络空间的子进程；
创建线程保留到真实 `Wait` 完成。不可只在已经多线程的子进程里设置一次并宣称全部线程受限。

监听端点由父进程绑定，子进程只继承这个 TCP 监听描述符。私密配置只走匿名 Unix 通道，
不会写入命令行、环境或普通日志。父进程不将自己的独立 guard 继承给子进程。

## 子进程职责

读取私密配置前核对：非 root 身份、无附加组、真实 root Unix peer 与当前父 PID 一致、
父死亡信号为 SIGKILL、各线程有效/许可/继承/环境 capabilities 为零且 `NoNewPrivs=1`。
检查固定继承的 root-owned guard、有限且规范编码的 bootstrap、原操作、截止时间、
最小权限 Unix SQL 身份和监听端点；不调用读取全部 token/节点私钥的 `LoadConfig`。

子进程执行的是现有 `ServeVerificationConsole`。普通写操作、管理令牌 API、节点探测均不开放。
私有 bootstrap 可附带原安装中受保护的 UI 目录，由子进程通过同一服务提供入口和静态资源；
不允许绕过文件所有者、目录、链接与长度保护。目录批准仍属于原 root 安装协调器，不是浏览器选择项。
匿名通道的确认仅说明子进程已验证 SQL 身份，不是 HTTPS 已就绪；验收必须实际发出请求并检查响应。

## 退出与恢复

- 原绝对截止时间由父子双方独立执行，不用重新启动延长批准。
- 父进程停止：关闭控制通道，等待子进程取消服务；固定宽限后才强制终止，并等待真实退出。
- 父进程死亡：内核父死亡信号终止子进程，不能依赖未经验证的 PID 文件清理。
- 返回不是 SQL 连接排空或迁移成功证明；root 必须另查服务器连接清单、原阶段数据和 guard 排空。
- 普通启动封存保持不变。跨批准期间续期、源主机隔离和节点接管未包含在此组件中。

## 原生回归

配置恢复场景使用已存在的真实最低权限账号和受保护测试 ELF，执行错误凭据拒绝、
TLS 验证下的完整 HTTP 401/403、每线程身份/权限、独立网络空间、停止、到期、父进程死亡、
真实子进程回收和 MySQL 连接排空。测试后原封存字节及完整数据阶段必须保持一致。
同一进程还检查已安装测试页面及 JS/CSS 的实际字节、HEAD、CSP、未知 API/源映射/配置/写请求拒绝，
以及启动后资源权限漂移的拒绝；新增 `verification_static_ui_protected` 为原生必需证据。
此低层静态资源与隔离进程检查已有 `8fa0566` 的 Ubuntu22/24 成功报告；后续受管调用链仍须单独验收。
错误凭据场景必须确实到达最小 SQL 身份检查并拒绝，不能把任意提前退出当认证拒绝。
私有通道只回传固定故障阶段；未知错误文本一律归为未确认，不导出 SQL、凭据、路径或子进程 stderr。

测试专用 UID/GID 65532 不代表生产专用账户已安装；源记录仍为合成，不是完整主机迁移。
这组请求没有创建登录会话，不能称为成功登录、手机/桌面浏览器或 UI 验收。

### 路由检查的格式与安全条件

旧检查把 `/proc/<pid>/net/route` 必须只有一行视为没有路由。Linux
[v5.15](https://github.com/torvalds/linux/blob/v5.15/net/ipv4/fib_trie.c#L2712-L2736) 与
[v6.8](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/fib_trie.c#L2733-L2757)
在主路由表尚未创建时，会在输出表头前返回空序列。因此该旧检查既会拒绝合法零字节，
也会误接纳任意单行文本；它不是可靠的路由解析。两平台失败码与此吻合，但旧产物没有
保存具体行形态，仍待新原生运行确认，不能把源码推断称为已经观察到的客体内容。

新检查只接纳“真实读取的零字节”或“完整的内核表头”，读取异常、空白、损坏表头和任意
路由行均拒绝。同时进入已观察子进程的网络空间，以只读 rtnetlink 查询核对**全部 IPv4 路由表为空**，
不能仅凭空文件放行；`verification_network_all_ipv4_tables_empty` 成为配置场景必需证明。
主机路由、接口、防火墙均不修改，原 `CLONE_NEWNET`、线程权限和 HTTPS/SQL 条件保留。

Linux 启动边界测试也先创建独立临时网络空间，实际执行内核格式与全部 IPv4 表检查。
`kernel_route_snapshot_verified` 必须由该快速原生步骤产生，避免仅为格式错误等到完整恢复场景末尾。
零字节/表头/损坏输入的离线回归不是此原生证明；本机 macOS 不宣称运行过 Linux 网络空间。

## 受管入口的剩余接线与验收

1. **固定安装协调器批准**：延用 `verify_installation` 的完整清单、版本与字节核验，
   UI 固定取该版本的 `ui/`，不得另收路径。核对原操作、目标 seal、不可变数据阶段、
   TLS 发布、完整 SQL 账户清单及专用系统 UID/GID；不把上一条 `runtime-check` JSON 当授权票据。
2. **同一锁内的 Go 准备**：核心接线与固定 root 运行入口已实现，禁止嵌套封存锁；
   新原生场景仍待执行，不能使用无检查的成功回应。
3. **清理成功后才启动**：核心接线已实现，仍需新源码的原生证据。准备失败即退出专用
   协调进程，不能在长寿命进程里遗留原始 guard 后继续接纳另一操作。
4. **受管生命周期**：systemd 启动/状态/停止已接入固定操作、无自动重启，新增原生证据仍待取得。先实际验证 TLS 与原账户
   新会话、手机/桌面页面，再观察显式停止、原到期、父死亡及重复启动拒绝。`verified` 私有确认
   仅说明 SQL 身份已核验，不等于页面或服务就绪。
5. **停止后闭合**：确认父子真实退出、监听关闭、独立 guard 排空和 MySQL 无活跃/未认证连接；
   再核对原数据阶段允许的精确认证差异，执行原账户撤销流程。任何一步未确认都维持目标封存，
   不开放普通主控、节点接管或自动回源。

此顺序的验收仍必须来自原生 Ubuntu22/24 和最终同源码浏览器记录。
前台受管入口不代表快捷迁移完成，也不将完整源主机导出、单活切换或灾难回退提前标记为完成。

参考：[Linux no_new_privs](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html)、
[父死亡信号](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)。
