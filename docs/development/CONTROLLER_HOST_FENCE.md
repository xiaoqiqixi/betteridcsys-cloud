# 主控迁移：源端进程准入保护

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

仍需真实 MySQL/HTTPS 这条新入口完成验收、更完整的并发与在途请求测试、旧版本能力核对、只停止并持久 mask 受管理的主控/心跳单元、重启复核及完整源隔离回执。完成这些才可关闭 M01。M02加密导出、M03空目标恢复、M04双活防护/接管回退、M05后台、M06跨主控实例迁移仍未交付；没有“导出后直接导入运行库”的捷径。
