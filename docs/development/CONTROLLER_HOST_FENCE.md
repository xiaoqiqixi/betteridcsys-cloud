# 主控迁移：源端准入与服务隔离

这是 M01 的运行时基础，不是可交付的主控搬家向导。统一安装入口不受影响。现有 Release 尚未包含以下源码；不要用旧二进制测试后宣称源主控已隔离。

## 当前接口

所有操作仍通过 `aster-controller`，没有另写一个脱离实际服务的锁演示程序：

- `migration-capabilities`：无秘密能力查询；明确 `migration_ready=false` 和 `export_restore=false`。
- `migration-status -config …`：检查本机控制身份的状态。`active` 表示未停写，`draining` 表示已有受保护进程未退出，`fenced` 表示已阻止新进程且旧受保护进程已退出。
- `migration-fence -config … -operation <32 位小写十六进制 ID>`：持久记录同一停写意图；同 ID 重入只查询原阶段，不重置、不重新下发任务。
- `migration-cancel -config … -operation <原 ID>`：仅在**尚无导出/接管**的当前阶段撤销。任意旧进程尚存、ID/配置不匹配均拒绝。撤销历史保留，不能重复使用已撤销 ID。不会自动启动服务。

这些接口仅供后续本机迁移执行器与验收调用，不加入普通后台用户的公开操作菜单。

## 实际接入

正常命令在读取 DSN、连接 MySQL 或访问节点前取得进程生存期共享锁，覆盖 `serve`、schema 迁移、首个管理员、心跳、维护、注册、财务派发和实例派发/对账。所有副作用仍走现有逻辑；没有修改财务金额、支付或历史快照。

`serve` 每次接收 HTTP 请求先检查隔离标记，维护时返回完整 HTTP503，而不是成功数据。后台监视持久标记并触发原服务关闭：停止自动 sweep，等待 HTTP Shutdown 完成，清理执行器。已发出但不能确认的任务仍由现有持久状态表示，不重发、不改成成功。最后的共享锁只在 **OS 结束进程** 时释放，不能在监听 socket 刚关闭或执行器关闭超时时提前宣布排空。

源服务下一次启动依旧拒绝；明确隔离退出码为78，生成的 systemd 单元设置 `RestartPreventExitStatus=78`，不制造循环重启。主控及心跳单元只增加私有 `StateDirectory=aster-controller`，不放宽其他系统目录权限，不接触节点、libvirt 或客户 VM。

## 持久化与安全边界

- 固定 `/var/lib/aster-controller/<controller_id>/`，root 私有；不接受路径、owner、shell、下载地址或环境覆盖。仅本地持久 ext4/XFS/Btrfs；拒绝 NFS、tmpfs、overlay 等不能据此证明重启持久性的部署。
- 逐层 openat / NOFOLLOW 检查；文件0600、单硬链接、4096字节上限。配置 ID 不能跨目录。
- 控制锁串行化准入/停写/撤销，运行锁观测实际进程。新意图和隔离标记先 fsync 文件及父目录，再返回成功。损坏/截断/权限漂移/链接均停在失败，不自动删除重建。
- 同一主控身份的不同配置也受同一个隔离标记约束；解除需要原配置摘要。配置修改不是绕过停写的办法。
- 状态始终报告 `source_isolated=false`、`migration_ready=false`：共享锁只能观察采用新协议的**本机进程**，不能证明旧二进制、另一主机、systemd 启动源或目标接管已隔离。这不是分布式 fencing token。

## 验收与剩余工作

公开 CLI 能力测试已在本地真实子进程执行。Linux22/24 CI 新增真实二进制测试：回环 MySQL 握手刻意悬挂一个实际 `check` 进程，确认正在排空；其余写入命令必须在 DB I/O 前拒绝；实际进程退出后才能撤销；覆盖重入、不同配置/ID、损坏、权限、符号链接、硬链接与错误脱敏。该 listener **不是 MySQL**，不把它计为实库验收，也不证明重启或 systemd 隔离。

另已增加真实 MySQL/HTTPS 验收入口：在 native-mysql 私有实例中创建独立库，运行实际 controller migrate、bootstrap-admin 和 HTTPS 服务；植入两份合成 sending/uncertain 记录；由持久标记触发服务自行退出，比较全库数据快照，撤销后原身份重启再次比较。该任务的执行结果以对应提交 CI 为准，未执行前不记为通过。

`1a74e20a864b6f2c39c30699820ce7b8d9b9f515` 的[CI 40504806662](https://github.com/xiaoqiqixi/betteridcsys-cloud/actions/runs/40504806662)中，两平台真实 CLI 和实际 MySQL/HTTPS 新入口均已通过：两个未知任务及全库行快照未变，实际 HTTPS 进程自行排空、同身份恢复通过。其余总计 10 个任务成功，但 Ubuntu22 TCG 原生安装任务超时，因此**整轮 CI 失败，不可作为发布通过证明**。失败产物 `12735024037` 的 ZIP SHA256 为 `d2e3031585353e126ec28a6f389312b321f7e5443388e00cff58b2cdf3f83646`；1170秒时已完成 libvirt 准备和重入，进入实际镜像验证，1200秒整机上限在最终检查前到期。本轮将整机上限改为1800秒，保留40分钟任务上限、所有断言和禁止自动重试；重新执行结果另记。

## 源服务隔离执行器

新增随主控包交付的 `templates/host-management/controller-migration.py`，与相同版本的安装器辅助模块相邻。通过已安装的实际 controller 能力接口要求 `host_migration_seal=true`，旧版本虽有 runtime fence 也不能冒充新隔离协议。检查固定安装回执、完整包清单、文件摘要/模式、当前配置、机器身份、主控单元、批准心跳模板、实际服务 PID/可执行文件/参数及 cgroup v2；未知单元或 drop-in 拒绝，不覆盖管理员配置。

- `plan` 只读，不连接数据库、不停服务。
- `isolate` 先使用真实 Go 停写协议，随后持久封存 host intent。普通 `migration-cancel` 无法解除该封存。
- 主控原单元与 `/dev/null` 屏蔽链接用 `renameat2(RENAME_EXCHANGE)` 原子交换，保留原 inode 和摘要；心跳实例使用 `RENAME_NOREPLACE`，不替换模板，不覆盖外来文件。每步记录与目录 fsync；按原 ID 重入检查实际文件位置，不盲目重复交换。
- daemon-reload 后停止已核对的 timer/service，重新核对持久 mask、PID、空 cgroup 与运行锁，再记录源隔离回执。`status` 每次重查，回执本身不等于成功。
- 导出前 `resume-source` 仅恢复原 inode/模板及原配置下的准入，不自动启动服务或改变 enable 配置。存在导出边界记录时拒绝；恢复中断可按同 ID 继续，已完成恢复可查询。
- 不记录密钥或 DSN，不开放自定义路径/URL/shell/unit/force；不修改节点、客户 VM、财务金额、支付或历史快照。只对受管理启动源及采用新协议的本机进程负责，不能证明外部主机或管理员绕过管理器运行的旧程序已隔离。隔离状态不授予目标接管许可，`migration_ready` 始终为 false。
- 无日志的 mask 暂存文件、损坏记录或外来 inode 会停在需要人工检查的隔离状态；不声称每一种断电窗口均已自动恢复。

新系统级验收入口使用**实际安装器 --allow-development** 安装同提交真实 ELF 和明确标记的最小 UI 夹具；不是发布包验签或视觉验收。通过仅回环字节 relay 连接原生 MySQL Unix socket，以保留真实单元的 PrivateTmp 沙箱。覆盖真实 systemd 主控、批准的心跳 service/timer、同 ID 重入、plain cancel 拒绝、持久 mask 拒绝启动、daemon-reload 后复核、错误 ID/导出标记拒绝、原 inode 恢复、不自动启动、人工启动后严格 TLS，以及全库行快照不变。Ubuntu22/24 两平台均列入 MySQL CI；结果必须以新提交实际任务为准，不能把本地语法/模型测试算作系统级通过。

`74b2edecbc71b252f0d8c2b2194a7c6c949b6283` 的[CI 40512617545](https://github.com/xiaoqiqixi/betteridcsys-cloud/actions/runs/40512617545)已完成：10/12 成功，两个原生 libvirt 环境均通过，但两个新增 systemd/MySQL 用例都在真实安装器 apply 阶段失败；基础 MySQL/HTTPS fence 用例仍通过。失败时确认自有资源清理完成。**系统级隔离尚未通过**，不能将 Go/浏览器绿灯挪用为其证明。后续增加只允许静态白名单的安装器错误诊断，不输出任意 stderr、DSN 或密钥。

恢复路径进一步改为先核对全部单元/屏蔽 inode，再撤销任何一个屏蔽，避免发现外来主控文件前已部分恢复心跳定时器。计划额外拒绝可识别的非本安装版本 `aster-controller` 进程，不终止它们；仍不声称能识别管理员改名运行的任意旧程序。新实库负例包括实际未纳管主控副本、drop-in、外来 mask inode、配置漂移及拒绝后的不变性；其结果须等新提交实测。

### Hosted runner 环境差异与材料绑定

`675bef0cf85685ae31b248e3cdbcdaea9a547b69` 的 [CI 40516096261](https://github.com/xiaoqiqixi/betteridcsys-cloud/actions/runs/40516096261) 为 9/12 成功：两个 systemd/MySQL 用例仍被真实安装器的路径保护拒绝；浏览器任务在准备阶段下载字体时超过900秒，未进入浏览器断言。两个原生 libvirt 安装任务通过，不能据此替代另外三个失败项。

`73247535d52c64d0a797767c2dde326da406346b` 的 [CI 40519867358](https://github.com/xiaoqiqixi/betteridcsys-cloud/actions/runs/40519867358) 在22/24均定位到相同原因：实际 `/opt` 是 root 所有、非符号链接、模式0777。**生产安装器拒绝可被其他用户改写的安装祖先是正确行为，不放宽校验。** 新夹具只在确认未装云/财务系统的独占 CI 主机上，持有 `/opt` 原始目录 FD，将已知0777临时收紧至0755；只允许已知两种模式，不递归 chmod、不 chown、不处理未知路径。停止并删除本轮自有服务和文件后，核对同一目录 inode/设备/owner/group，再恢复原模式。成功报告必须等待此清理完成，并明确 `unmodified_host_image_acceptance=false`；这是经过明确环境准备的 systemd 测试，不是原始 hosted 镜像直接安装成功。

维护身份新增配置所引用的 DSN、令牌、服务端及节点 TLS 材料摘要，防止配置路径不变而底层材料已替换时继续原操作。原文和秘密不进入输出。实库夹具还独立检查原 MainPID 的进程启动身份已消失、被屏蔽服务 MainPID/ControlPID 为0，并注入令牌内容变化检查拒绝。新断言仍须在实际 Linux CI 执行；本地 Python 语法检查不算通过证明。

仍需本轮实际 systemd/MySQL 结果、更完整的并发与在途请求、原生 OS 重启复核及故障窗口验证。daemon-reload **不是**操作系统重启。完成这些才可关闭 M01。M02加密导出、M03空目标恢复、M04双活防护/接管回退、M05后台、M06跨主控实例迁移仍未交付；没有“导出后直接导入运行库”的捷径。

实现语义参考：[Linux renameat2](https://man7.org/linux/man-pages/man2/rename.2.html)、[systemd 单元加载与 mask](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)。Ubuntu22/24 的实际行为仍由分发版测试确认，不以最新版手册替代验收。
