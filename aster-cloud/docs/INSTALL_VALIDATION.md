# 主控 / KVM 被控安装器验证边界

本页记录安装器安全回归的范围，**不是正式发行或整机安装验收声明**。
本轮实现只接受唯一官方候选身份 `cloud-v0.1.0-rc.1` / `0.1.0-rc.1` /
`prerelease`；这**不是已发布 Release 或下载成功的记录**，没有 stable/latest
回退。开发候选包、Python 合成载荷、mock runner 或文件系统单测均不能称为
真实主控 / KVM 安装、升级、恢复通过。财务 `v0.5.9` 不是 Cloud 发行物。

正式角色命令只取实际发布后的
[cloud-v0.1.0-rc.1 Release body](https://github.com/xiaoqiqixi/betteridcsys/releases/tag/cloud-v0.1.0-rc.1)。
若 Release body、完整 assets 或 attestation 缺失，必须停止，不用 `/main`、
财务包或占位 curl 冒充可上线的一条命令。本页不记录官方发行已经完成。

## 本地安全回归

仓库根目录运行：

```sh
python3 -B aster-cloud/deploy/ci/test_cloud_installer.py
python3 -B aster-cloud/deploy/install/test_install.py
python3 -B aster-cloud/deploy/ci/test_cloud_release_verifier.py
```

测试只在 `tempfile.TemporaryDirectory` 内构造**合成** tar.gz、manifest
和输入文件。所有凭据字符串均为测试标记，不读取用户真实凭据。测试进程
禁止实际 `subprocess.run` 和网络连接；个别系统边界通过 Python `unittest.mock` 替换，
不会执行 sudo、apt、systemctl、网络配置、虚拟机命令或远程操作。
固定生产路径的节点 fixture 在测试进程内映射至临时文件；没有创建真实
`/etc/aster-node` 或 `/var/lib/aster-*`。此映射不在生产 CLI 中暴露。
生产 CLI 不提供 root-prefix、任意 runner、跳过 TLS 或绕过所有权的测试开关。

回归核对的公开边界：

- `verify_bundle`：只读验证外部 SHA256 和 manifest 中每个文件的 SHA256、
  大小、权限、角色与平台，不执行包内程序；库存与包成员必须完整对应。
- 恶意归档：拒绝绝对路径、目录穿越、反斜线 / 非规范路径、PAX 路径穿越、
  软链接、硬链接、目录及设备/FIFO等特殊项、重复成员、重复 / 非法 manifest、
  缺失 / 多余文件和超限输入。上界用测试进程内的常量替换触发，不分配巨型包。
- 哈希 / 解包竞争：完整外部 SHA 完成后替换源路径，或原 inode 写入另一份
  同大小合法包并恢复 mtime，均只能拒绝或返回原先已哈希的字节。
  PAX / GNU 元数据声明在读取载荷前被拒绝，避免 stdlib tar 迭代器提前分配。
- `make_plan` / `execute` 的默认 plan 和 dry-run：开发路径非 root 可读、
  无安装写入、不执行宿主配置命令。官方 RC 路径额外调用本地 pin 住的 gh，
  离线复验 publisher proof；不联网、下载、写缓存或执行 APT/DB/service apply。
  root 私有 proof 仍需调用身份有权限读取。不将开发候选包伪装为正式 release。
- apply：非 root 必须拒绝；具体私有审批、已有 / 部分安装、未就绪节点和
  故障恢复结果以实际测试项为准，不能从 plan 的通过推断 apply 已经安全完成。
- 配置 / 恢复：已有配置与 unit 不同即拒绝；部分 init seed 的 token 保留，
  不重写 init 原配置；重复安装、换包或改变向导意图不得默默恢复。
  当前 schema 仅运行 runtime check；需要迁移时必须同一专用数据库、不同
  非 root 本机账号的独立迁移 DSN，并以单独 0600 配置执行，不能写进 serve unit。
- 节点：未就绪 preflight / doctor 不启动；qemu-img info / check 使用固定参数，
  没有修复 `-r`，拒绝 raw、backing、external-data、encrypted 和畸形信息。
  自身 TLS、镜像、state/storage/artifact/inbox 限于固定 unit 可见目录。
- 控制面身份：节点审批即使显式提供 controller client cert/key 也拒绝，
  向导不采集此身份。节点只有本机 doctor / systemd active / TCP listener
  检查，结果必须为 `node_started_pending_controller` / `active-unadmitted`。
  **这不是 mTLS 健康探针，也不是已加入主控**；真实 mTLS 核对必须从主控端
  使用仅保留在主控端的 client 私钥执行。主控 TLS 健康失败则不 enable 服务。
- 可选原生依赖 / MySQL：默认关闭，带 opt-in 的 plan 仍不执行安装命令或生成秘密。
  测试核对固定包列表、独立 HTTPS Ubuntu signed-by 源、禁升级 / 移除、拒绝
  非批准 daemon 模拟计划、临时 policy 的独占创建与 inode/内容绑定删除、失败后
  显式原计划恢复。已有 policy、MySQL 配置、数据或 drop-in 均拒绝覆盖。
  普通节点工具列表不含 daemon；新增显式 `--prepare-libvirt` 才批准固定官方
  `libvirt-daemon-system` 及其依赖。该软件阶段不要求 `/dev/kvm`，但最终
  node preflight/镜像/doctor gate 完全不放宽，仍不能称为真实 KVM 端到端安装。
- libvirt 软件准备：真实 fresh guard 直接在虚拟读取边界下执行，逐项拒绝
  数据库/财务/virt 路径、foreign units/drop-ins/masks、已有 policy 和不足
  2GiB `MemTotal`。包事务前持久 mask 全部已枚举 vendor service/socket，
  只启动 `aster-cloud-{libvirtd,virtlogd,virtlockd}.service`。保留官方 AppArmor、
  QEMU 用户和 fresh 磁盘上的 vendor default XML，不删除 XML 假装隔离成功。
  own libvirtd 以 `BindReadOnlyPaths` 将专用空 networks/autostart 映射到
  `/etc/libvirt/qemu/networks`；核对有效 unit、真实 PID/exe、namespace inode
  和只读 mount 标志，再做固定 readonly `virsh qemu:///system` 查询。
  fresh 视图不得有 domain/network，接口/firewall 结构前后必须一致；仅忽略
  流量计数/时间注释，规则、chain policy、source/target 变化仍拒绝。
  软件状态只能为 `libvirt-prepared` / `kvm=not-asserted`。
  既有活动 daemon 只读保留、不安装/重启/删配置/改已有网络；inactive daemon
  不被隐式 socket-activate。失败保留 masks/receipt；start/enable 丢 ACK 也按
  不确定处理，只对 owned units 尝试 disable/stop；resume 不得换计划或新加批准。
- 数据库 bootstrap：只允许本机 root Unix socket 的一次性管理操作；实际 runtime
  必须是新建的非 root DML 身份，迁移为另一个非 root DDL 身份。测试核对 SQL
  仅走 stdin、client 不读 `/root` login-path、不继承密码环境变量；MySQL 生成随机
  密码的回包只写入 0600 DSN，不进入 SQL、argv、结果输出或日志。
  外来数据库、任一目标账号碰撞、异常隐式角色 / grant 语义均在创建前拒绝。
  恢复需要原 server UUID / names / nonce；CREATE 丢回包且凭据未落盘时保留
  数据库与账号，不自动 reset / recreate / adopt。runtime grants 仅四项 DML，
  拒绝 global、额外 DDL、role、GRANT OPTION 和未转义数据库 wildcard。
- 新 MySQL 仅依据本操作的 fresh receipt 和 exact socket-only drop-in 启动；
  classic TCP 与 MySQL X 都须关闭。服务启动丢回包也按可能已启动处理，尝试
  停止本操作的精确 unit，不写成“从未启动”，不 enable / 宣称 ready。

测试中的文件内容、模式和拒绝断言不能证明真实 TLS 证书链、MySQL 账户隔离、
KVM 设备权限、systemd sandbox 或宿主网络已正确配置。安装器不应重新生成、
覆盖或输出未知 / 部分安装的已有密钥、DSN、token、配置、journal 或 fence。

APT 包的 maintainer scripts 通常会管理服务生命周期；临时 policy 只能约束
遵循该机制的调用，并非所有包脚本无副作用的证明。原理参见
[Debian 服务策略](https://www.debian.org/doc/debian-policy/ch-opersys.html#running-init-scripts)
及 [invoke-rc.d policy](https://manpages.debian.org/trixie/init-system-helpers/invoke-rc.d.8.en.html)。
MySQL 的 `--no-login-paths` 是 8.2 才新增，不能盲用于 Ubuntu 的 8.0 client；
当前代码使用私有 HOME / login-path 隔离，仍需目标主机实测。
参见 [MySQL 官方说明](https://dev.mysql.com/blog-archive/new-client-option-no-login-paths-turn-off-login-path-file-processing/)。

## 唯一 RC 的 publisher 验证边界

初始 bootstrap 使用 Release body 的**完整 immutable commit** HTTPS 地址，
是操作者必须审阅的信任起点，不是脚本拿同源 SHA 后“自我证明”。后续代码
必须通过匿名 GitHub/Sigstore attestation：固定代码 hash 的官方 gh 二进制及
固定官方 trusted roots，绑定 repository/owner 数字 ID、tag、source SHA/ref、
workflow、GitHub-hosted runner、trigger 和 verified transparency timestamp。
不依赖用户 token，不接受 self-hosted publisher 或 TLS 绕过。

签名 release manifest 完整绑定每个 asset 的 name/size/hash；本地私有 receipt
仅记录证明材料，不因 `verified:true` 获得授权。release ID 只记录 HTTPS API
观察值以防混合一次下载，**不是签名授权**。installer 在 plan/apply 前离线
复验 manifest、capsule、role bundle 三份 publisher 绑定，核对 capsule 三个
代码邻居，拒绝多余 import、软/硬链接、公开权限、非 pin 住的 gh/roots。
`--allow-development` 不能批准 release，正式 receipt 也不能批准开发包、其他
RC 或 stable。原 tar/manifest 的每文件与完整外部 SHA 校验继续生效。

新增 **19 个独立 publisher-policy methods** 使用合成证书/签名输出模型，
成功例确实到达三次固定离线 verifier seam，并检查 flags 互斥兼容、匿名环境、
无写入；负例逐项更改证书身份/SHA/owner/runner/trigger/timestamp、asset 绑定、
capsule、私有权限和未知邻居。**mock gh stdout 不是密码学验签通过**。
`--download-only` 本身允许写私有下载/proof，再执行实际已认证 installer 的
只读 plan；它既不是零写入 bootstrap，也不是 host apply / VM 通过。

## 当前 Ubuntu 22.04 / 24.04 TCG gate（新提交待 CI）

新增 [native-libvirt contract](../deploy/ci/libvirt-native.md) 规定使用 Canonical
签名校验且固定 hash 的新 Ubuntu 镜像，在隔离的 TCG guest 内真实执行 APT、
PID-1 systemd、生产 `prepare_libvirt` 与相同计划 resume。不能删除 runner
已有 MySQL/libvirt 路径冒充 fresh host，也没有生产 `skip-kvm` 开关或假设备。

必须真实核对 persistent vendor masks、owned units、root-only UNIX socket、
实际只读空 networks mount、virsh capabilities/空 networks、无 `virbr`，并对
宿主接口/路由/firewall 结构做前后对照。真实节点配置使用完整 Canonical
镜像、真实临时证书和有效资源限制；doctor 不能任意非零就算过，必须通过
非 KVM 先决检查并明确拒绝不存在的 `/dev/kvm` / hardware virtualization。

**范围收敛后的两个 Ubuntu gate 须按新提交重新执行，不继承历史 PASS。** Ubuntu26 暂缓；旧 26 失败及旧 14/15 记录不改写。 即使
随后通过，也仅证明软件准备和 missing-KVM fail-closed；TCG 不是硬件 KVM、
真实 VM 生命周期、物理上联、controller admission 或生产安装验收。

## 必须另外执行的验收

正式使用前仍需在专用、可销毁的 Ubuntu 22.04 / 24.04 amd64 主机分别验证；26.04 暂不支持：

1. 实际已发布 sole RC 的匿名完整下载、固定 commit bootstrap、真实 Sigstore
   proof、版本与构建 provenance。外部 SHA 不能单独证明发布者身份；发布链
   的 offline parser/mock 测试不等于一次真实官方下载/密码学验证成功。
2. 干净主机安装、故障中断后的人工核对、重复安装拒绝、配套升级、备份与
   数据库 / journal / 制品一致性恢复。不能只换旧 binary 或删新表降级。
3. 真实 APT 事务、维护脚本 autostart/默认网络边界、policy 中断恢复与所有权；
   独立 MySQL CREATE USER 随机密码回包、SHOW GRANTS 的真实字节 / wildcard
   语义、owner marker 与 Go migration/check 兼容性，及原生 socket-only 服务。
   主控独立 MySQL / schema、runtime DML-only 与独立迁移 DDL 账号的真实 grants、
   受保护配置与文件所有权、有效 HTTPS 链、
   真实会话和 CSRF、首管理员私密 stdin 初始化、服务重启及日志脱敏。
4. KVM 被控的 `/dev/kvm`、libvirt、镜像 / 存储 / bridge / filter / IP 池、
   明确 root 审批的双向 mTLS 与叶证书 pin、资源能力和维护状态。
   未就绪时必须保持不启动，不把“软件装好”说成“节点上线”。
5. 真实 VM 创建 / 关机 / 恢复 / 冷迁移、网络隔离、公网上联、跨宿主包流、
   故障注入与重启恢复。真实 KVM 验收仍为后置步骤。

既有真实 MySQL / 严格 TLS 浏览器门禁见
[浏览器门禁](../deploy/ci/NETWORK_BROWSER.md)，它的节点 RPC 是测试替身，
不能代替上述主机生命周期和 KVM 验收。开发安装器不修改金额、支付、币种、
历史商品 / 财务快照或既有财务数据库。

## 当前结果

2026-10-25，Darwin 本地离线结果：**108 个 installer-security + 14 个
installer-unit + 19 个独立 publisher-policy test methods 通过**（另含 subtests），
无 SKIP。它们只使用合成文件与替代系统边界，没有实际 APT、启动服务、
连接 MySQL、执行 gh 密码学验证或 KVM。与 packager 的 USTAR envelope /
metadata 往返兼容也只使用合成字节，不是真实包安装。

首轮 RED 在安装器文件尚未落盘时失败；后续 RED 还发现向导的
`is_loopback` property 调用错误及畸形镜像信息异常。归档前置元数据边界、
TOCTOU immutable snapshot 和权限分离分别补入独立回归。**上述通过不是
完整安全审计结论**；后续源码改动必须重跑，所有真实主机验收仍未执行。

依赖 / MySQL、真实002 FK源码对照与 migration-only REFERENCES、native
入口/transport、runner 隔离和新增 libvirt / RC 边界均在当前计数内，不沿用
旧93项结果冒充本轮。APT source/policy 用例显式隔离
宿主 precondition；独立用例仍调用真实守卫，只虚拟文件读取，逐项核对全部
数据库 / virt / finance 路径（存在及悬空 symlink）、节点内存 / KVM 字符设备，
以及 MySQL 配置 / service / binary / socket 路径的拒绝和干净证据通过。
本轮 RED 在模拟占用 runner 上复现提前拒绝，并发现原 node simulation 负例
没有到达 APT；修复后强制 update / simulate 各一次，危险计划不进入 assume-yes。
REFERENCES 只在专用数据库 migrator grants，
runtime 仍为 SELECT/INSERT/UPDATE/DELETE，不扩展 global/DROP/GRANT OPTION。
这批使用 Python SQL 边界模型，不启动 MySQL、APT、systemd 或任何 daemon；
不能称为真实 MySQL provisioning、干净 Ubuntu 安装或 KVM 验收通过。
额外 RED 发现并回归了启动丢 ACK 的错误“未启动”归因，以及旧 receipt
缺少 `native_options` 时可在 resume 引入新副作用的问题；旧 receipt 只按
原始无 APT / 无数据库 provisioning / 无 libvirt prepare 意图恢复，不因此
获得新的安装授权。当前计数不是完整安全审计结论，也不绑定尚未提交的工作区
SHA 为验收终点。

## 独立 native MySQL SQL / grants 合同门禁（结果绑定精确 CI revision）

`deploy/ci/check.sh` 在原有 disposable `mysql-native.sh` fixture 内强制执行
`deploy/ci/test_cloud_mysql_grants.py`。入口必须为非 root Linux amd64，且
`RUNNER_TEMP` 与四个 `ASTER_NATIVE_MYSQL_{ROOT,SOCKET,ADMIN_CNF,FIXTURE_ROOT}`
均严格匹配当前私有、当前UID所有、无链接别名的 native fixture 布局。
另外核对 socket 类型、mysqld PID / `/proc` executable / argv，以及真实服务器
basedir、datadir、socket、8.4版本和禁TCP状态。环境缺失或不符返回失败，
**没有 host mysql / host DB fallback，也没有 SKIP-success**。

仅借 fixture 原有 `aster_ci` 管理身份，在随机后缀的固定测试前缀下创建
两库两用户，碰撞不接管；凭据保留在0600私有client文件及私有HOME内，SQL
走stdin，参数不带密码。显式 `--defaults-file` 为第一个选项，随后才是
`--no-login-paths`，遵循 [MySQL 8.4 option-file 顺序要求](https://dev.mysql.com/doc/refman/8.4/en/option-file-options.html)。

门禁真实执行服务器 RANDOM PASSWORD / ATTRIBUTE / SHOW GRANTS，并仅在
测试模块临时替换 `provision.mysql_sql` transport 后调用生产 `verify_grants`；
不修改任何生产 root / owner guard。以实际 migrator grants 执行当前全部10份
SQL迁移；004确有6条 CREATE INDEX SQL，一并真实执行，不冒称只验证了Go逻辑。
同时核对002 FK、runtime DML成功而CREATE/ALTER/GRANT/DROP失败、migrator
DDL成功但无global/邻库权限，以及数据库下划线不得作为wildcard授权邻库。
负例先确认同一已认证身份执行了SELECT，再接受权限错误码；auth失败或语法错误
不能充当权限拒绝证明。

清理只对本脚本 nonce + server UUID 标记明确绑定的新库/用户执行DROP，
不凭名称接管；未知对象保留给外层拥有的fixture整体清理。stdout回执只有
固定scope/checks、迁移版本/hash、passed和cleanup状态，不输出SQL、grants原文、
密码、DSN、token或原始client诊断。

本机无 native fixture，guard 调用返回 `passed:false` / exit1，未在本机运行
数据库权限门禁。上面的108项仅包括纯guard/transport单测；真实SQL结果须
绑定同提交 GitHub native MySQL job，精确历史/当前 CI 记录见
[总验证记录](VALIDATION.md)，不能把旧 revision 的通过自动沿用到新发行。
此门禁仍不覆盖生产root socket bootstrap、APT、systemd、整机安装/升级恢复
或KVM，也不能替代本轮尚待执行的 TCG libvirt gate。
