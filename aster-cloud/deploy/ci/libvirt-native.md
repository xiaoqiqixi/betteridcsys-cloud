# Owned native-libvirt software preparation gate

This is a **TCG virtual-machine CI fixture**, not a production installer, Docker
deployment, KVM guest acceptance, or permission to use the finance host. Local
offline contract tests do not establish that a native boot succeeded.

## Entry point and host prerequisites

```sh
python3 -I aster-cloud/deploy/ci/libvirt-native.py \
  --ubuntu 22.04 \
  --source-root "$GITHUB_WORKSPACE" --source-sha "$GITHUB_SHA" \
  --output "$RUNNER_TEMP/cloud-libvirt-native"
python3 -I aster-cloud/deploy/ci/test_libvirt_native.py
```

`--ubuntu` accepts only `22.04` and `24.04`; `26.04` and unknown versions are
rejected before fixture execution. Both supported guests run on Ubuntu 24.04 host runners. The host must be non-root Linux amd64, with Go **1.27.3**,
Python 3.10+, `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, `gpg`, `gpgv`,
`ip`, and an existing read-only firewall inspection tool (`nft`, otherwise both
`iptables-save`/`ip6tables-save`). Only the read-only firewall dump uses `sudo -n`.
The harness never installs a firewall or libvirt daemon on the host, purges host
packages, modifies host NICs/routes, or stops host services. No Node/npm is needed.

## Image and execution trust

- Images use **dated** Canonical cloud-image directories: Jammy `20261020` and Noble
  `20261017`; full image SHA256 values are pinned in code.
  Neither `current`, `release`, nor `latest` is used for image resolution.
- The vendored **public** UEC image key is independently pinned by complete-file
  SHA256 and primary fingerprint
  `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`. An isolated GnuPG home plus `gpgv`
  verifies the signed SHA256SUMS before image bytes are accepted. HTTPS verification
  stays on and redirects cannot leave the fixed cloud-image origin.
- QEMU is unprivileged, **TCG only**, with `max,vmx=off,svm=off`, 3GiB RAM, its
  own qcow2 overlay, a read-only NoCloud seed, and a read-only raw second drive
  containing the **complete signed original QCOW2 file bytes**. The latter is
  copied and rehashed inside the guest; no fake boot image is generated.
- There is no SSH, host port forwarding, TAP, bridge helper, 9p/host filesystem
  share, or imported repo credentials. Only three fixed files and a real compiled
  `aster-node` enter the seed. Subprocess environments exclude inherited tokens.
- User networking has `restrict=on`. Two fixed guest forwarding rules provide
  TLS-transparent TCP relays solely to public IPv4 addresses of
  `archive.ubuntu.com:443` and `security.ubuntu.com:443`. Guest `/etc/hosts` maps
  these names to the two virtual forwarding endpoints. APT still verifies the
  original TLS hostname and signed Ubuntu metadata; there is no generic proxy,
  TLS interception, or arbitrary host/metadata access.

## Actual acceptance contract

The official guest must start with no pre-existing MySQL/libvirt workload. If it
does not, the gate fails; it never deletes a pre-existing workload to make the
fixture appear fresh. In this owned guest only, background apt/SSH units are
disabled to avoid unrelated timer races and unintended login listeners.

The guest invokes the production
`prepare_libvirt(root_private_state, resume=False)` and its explicit resume path,
without mocks or a production safety bypass. It requires real APT installation,
real PID-1 systemd, active owned libvirt/log/lock units, persistent vendor-unit
masks, an effective read-only empty-network mount in the daemon namespace,
real Unix-socket `virsh qemu:///system` queries/capabilities, no visible default
network, and no `virbr` interface. Official package-created on-disk default XML
may remain, but the owned daemon must not see or activate it.

The node config uses a real signed Canonical image, its exact whole-file hash,
real ephemeral CA/server/client certificates, protected paths, and valid bounded
allocation settings. **Any doctor nonzero exit is not enough.** Its actual JSON
must identify this node and protocol, include every expected doctor check,
explicitly fail `dev_kvm_read_write`, and pass all non-KVM prerequisites. A
configuration rejection, missing binary, unavailable libvirt, missing image or
bad storage path cannot be counted as a KVM-denial success. `/dev/kvm` is never
fabricated. `kvm_ready` must remain false.

## Bounded cleanup and public evidence

The output directory is new/0700 for each invocation. Owned subprocess groups
use `start_new_session`; deadline, interruption and exception cleanup target only
their original child group, TERM then bounded KILL. VM runtime is bounded to
20 minutes. Private serial/seed/disks/build scratch are removed. Host address,
route and firewall rule structures are compared before/after; dynamic counters
and lifetimes are excluded, not policy content.

Only upload `summary.json`, `guest-report.json`, `image-provenance.json`. **Never
upload serial logs, cloud-init logs, seed data, private keys or raw syslogs.** A
passing summary binds `ubuntu`, `source_sha`, `image_sha256`, `real_apt:true`,
`real_systemd:true`, `libvirt_prepared:true`, `kvm_ready:false`. Failure/missing
proof is a hard failure, never a skipped or claimed KVM-ready result.

Failed guest reports expose only fixed `phase`/`code` enums and a small optional
`diagnostics` object: up to four fixed failed-command categories, whitelisted
dependency/libvirt receipt statuses, and whitelisted completed-step names.
The command observer transparently calls the original production `run_fixed`
with unchanged arguments, results and exceptions. It does not export command
arguments/output, paths, policy nonces, receipt bodies or keys. The host filters
failure reports before export and fully validates successful reports before
writing them; a forged nested value cannot enter a public artifact. APT
update/simulation/install, systemd start, and mount-isolation failures therefore
remain distinguishable without uploading raw guest logs. Relays exit when their
QEMU input pipe closes rather than lingering on a remote HTTP keep-alive.

## Primary sources and remaining validation

- [Canonical released image directories](https://cloud-images.ubuntu.com/releases/)
- [Canonical public-images verification guidance and UEC fingerprint](https://documentation.ubuntu.com/_/downloads/public-images/en/latest/pdf/)
- [QEMU user-network restriction and guest forwarding](https://www.qemu.org/docs/master/system/invocation.html)
- [NoCloud local seed datasource](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)
- [QEMU 8.2 TCG CPU feature implementation](https://raw.githubusercontent.com/qemu/qemu/v8.2.0/target/i386/cpu.c)
- [Ubuntu architecture variants](https://documentation.ubuntu.com/project/how-ubuntu-is-made/concepts/supported-architectures/)

Historical 26.04 work used QEMU 8.2 TCG AVX/F16C/FMA and AVX2/BMI support
with the `max` CPU. That source assessment was **not a successful 26.04 acceptance
record**. Ubuntu26 is now deferred: its image/CLI/sandbox allowlist and required
job are removed from the current executable scope, not declared passing. A future
26 reintroduction needs separate review and full verification.
None of these tests establishes real KVM creation, physical guest networking,
controller admission, provider ownership, or production-host installation.

## 首次 native CI 失败与诊断修正

`766c055` 的三份 Ubuntu 镜像均实际通过签名与完整 SHA256 校验，不能因此称安装成功。
24.04 / 26.04 在真实 APT simulate 失败，只有 owned policy-created，尚未安装 libvirt；
22.04 在固定 1200 秒 VM deadline 退出，没有收到最终 guest report。原始脱敏结果保存在该 CI artifact。

后续 fixture 不延长超时、不重试包安装、不把失败改成 SKIP。增加只含固定阶段 / 命令类别
start-done-failed 与秒数的 serial 心跳；原始 serial、stdout/stderr、nonce、路径和秘密不上传。
收到最终 report 即先做绑定 / 完整 schema 校验并保存，避免关机超时丢失已经产生的诊断；
超时仍失败，不能因 report 存在就通过。失败 report 不再误套成功 schema。

宿主网络仍逐项比较真实地址、路由与规则。只略去 IP 运行期 lifetime / last-use 与 nft
**counter 对象内部**的 packets/bytes；限额、规则字段中的 bytes/rate 必须保留，不能通用删键。
失败摘要另给固定 category、schema field path 和各部分 SHA256，不输出地址 / 链名 / 规则值。
任何结构变化仍 hard-fail，不把未知 runner 变化推定为无害。

APT 错误只接收 production `ProvisionError.code` 的固定白名单，未知错误仍拒绝；
新增分类不放宽正式验证或变更执行器的原调用、返回值和异常。所有离线合同是模型回归，
需下一精确 main SHA 的三套真实 Ubuntu CI 重新验收。

本地真实 pipe + socketpair 回归复现：旧 relay 在输入 EOF 时立即返回，丢失对端在 FIN 后
发送的完整响应（RED：实际输出为空）。现改为 `shutdown(SHUT_WR)` 后继续读取响应，
EOF 后最多 60 秒 drain、单连接总 deadline 300 秒，不放开地址检查；同一实际内核 I/O 测试已 GREEN。
这证明修复 TCP half-close 缺陷，**尚未证明它就是 CI 的 APT 根因**。
relay 另在 owned 0700 scratch 下写仅固定 host / nonce / event 的 0600 append 诊断；
主进程仅导出匹配本次 nonce 的静态事件计数，区分启动、DNS、非公网地址拒绝、连接与字节/EOF。
不导出 IP、nonce、原始异常或私有文件，也不绕过非公网 DNS 拒绝。

### QEMU / libslirp 子进程过滤器修正

代码级核对发现：QEMU 的 `elevateprivileges=deny` 将 `setsid` 与身份变更一起拒绝；
libslirp 在执行每条 `guestfwd ... cmd` 前调用 `setsid`，因此 helper 可在 Python 启动前即被 SIGSYS 终止。
不能简单关闭 sandbox 或放开 guest Internet。CI 使用独立、非 root、单线程 C launcher：
设置不可逆 NNP，复制官方原 PRIVILEGED 拒绝集合，**仅允许不提升权限的 session 创建 setsid**；
setuid/setgid/setpgid/setreuid/setregid/setresuid/setresgid/setfsuid/setfsgid 仍 KILL_PROCESS，
额外拒绝 setgroups/capset、i386 和 x32 ABI。QEMU 自身 obsolete / resource-control 与默认过滤继续启用。

launcher 从 owned 0700 cwd 仅允许精确的 35 项 QEMU 参数、三个固定镜像名和两个固定 TLS relay；
root-owned ELF64 QEMU 经 O_NOFOLLOW 打开并以同一 FD 执行，不接受任意程序或外部命令参数。
每次 Linux fixture 先真实 fork 自测：允许 setsid，全部被禁 syscall / i386 / x32 必须 SIGSYS，
不能把普通非 root 的 EPERM 当作成功。启动后另从实际 `/proc/QEMU/status` 核对 NNP=1、
Seccomp=2、filter 数至少宿主基线+2、四个 UID/GID 保持原非 root 身份，
CapInh/CapPrm/CapEff/CapAmb=0；不冒称无权限清空的 CapBnd 也为零。

仿真宿主固定 Ubuntu 24.04 + 官方 libslirp 4.7.x，避免旧 4.6 的临时 helper socket 使用
INADDR_ANY；**当前 guest 分别是验签的 Ubuntu 22.04、24.04**，不能将宿主版本偷换成 guest 兼容证据。
relay 记录本次 nonce、PID 和 starttime 的 private ownership；QEMU 退出后不按泛进程名杀，
对精确身份和命令复核后使用 pidfd 终止并等待退出，再确认无本次 relay 命令存活。
单连接 DNS/连接/传输总限时 300 秒、写侧 EOF 后 drain 最多60秒。成功 summary 必须含实际
`host_process_isolation_verified`、`sandbox_selftests_passed`、`relay_cleanup_verified` 三个真值；
未完成或超时不能取得这些通过声明。C helper 仅 CI，不进入生产包或改变 libvirt 生产策略。

APT plan 拒绝诊断仅观察生产 `apt-get --simulate` 的实际成功返回，不改 argv、返回值、
异常或安装门禁。输入最多 1 MiB；输出仅三种固定分类（remove / installed-package-version-change /
unapproved-network-daemon）、最多12个预先枚举的 Ubuntu 软件包名、未知名数量（上限255）和
截断标志。版本、来源、地址、路径、原始输出与任意未知包名均不导出；宿主再次验证整个字段合同。
这只能定位门禁为何拒绝，不能把拒绝改称通过，也不能借此升级预热镜像或移除原有软件。

128a86d的24来宾已完成软件准备，但宿主最终地址接口数量变化，整项仍失败；不能因为来宾报告成功而绕过宿主保护。
后续在VM启动前增加第二次完整快照核对，原最初baseline不移动，结束后的完整核对也保留；两个检查点都必须真实不变。
接口差异只附数量、ifindex、固定名称类别、link type和地址族数量，不输出实际名称/MAC/IP；超过32条诊断详情明确标记并保留总数。
这是证据显示上限，不截断实际快照，也不把Docker/veth/默认网络排除出比较。未知宿主变动仍拒绝，不能把诊断新增描述成根因已修复。

dab0167的22来宾在启动前已被拒绝：原baseline有3个接口，准备阶段后有4个；新增接口为无IP的ether且有master。
两次完整快照均记录该差异、路由与防火墙hash不变，QEMU未启动、guest report不存在。
这排除了本轮来宾libvirt安装作为这次变化的来源，尚不能归因于某个宿主服务或准备子进程。

只在原始完整快照已不相等时，另读`ip -j -d link show`作诊断；详细结构中的运行期timer不混入或重置原准入快照。
公开诊断只追加固定link-kind和master类别，不导出接口/主桥实际名称、地址、linkinfo任意字段，也不把不读取地址的link命令假称地址证据。
诊断采集失败只记不可用，原始拒绝不变。`veth`/`docker_bridge`只是结构类别，不是进程归属证明或忽略规则。
最终检查仍必跑；若已有先发失败，保留其原固定错误码而不是用最终失败覆盖它。最终proof仍保留，
缺失或不相等绝不能产生通过；即使最终网络恢复原样，也不能挽救启动前已失败的检查。
回归直接执行真实`execute`控制流，覆盖启动前/来宾失败、最终差异/采集不可用和临时变化恢复，全部维持拒绝。
