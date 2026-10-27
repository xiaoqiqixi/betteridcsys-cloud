# Cloud 独立预发布与下载信任链

Cloud 的第一条官方候选通道是 **`cloud-v0.1.0-rc.1` / linux-amd64**。这不是稳定版，
`production_ready=false`、`real_kvm_accepted=false`。源码只在 `main` 更新；新 Cloud 标签
与 Release 不覆盖财务的 `v*` 标签、资产或 `latest`。真实下载与结果以
[Cloud Release](https://github.com/xiaoqiqixi/betteridcsys/releases/tag/cloud-v0.1.0-rc.1) 为准，
未发布、缺资产或 gate 失败时不能声称通道可用。

2026-10-27，首个RC已完成实际双构建、独立签名、公开九资产与Ubuntu24两角色真实验签/生产plan；见[公开验收](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/CLOUD_PUBLIC_ACCEPTANCE.md)。后续main新增22/24×两角色的[独立公开复验入口](../../.github/workflows/cloud-public-prepare.yml)，实际结果须单独记录，不能预填通过。

## 每个角色一条安装命令

Release 正文提供 controller 和 node 各一条命令，HTTPS URL 固定到**完整 40 位源码 SHA**，
不是可变的 `/main`、`latest` 或任意输入 URL。初始 Python 脚本是操作者审核并信任的入口；
第一次取得它依赖 GitHub HTTPS 与所批准的精确提交，不声称它能自证自身。

运行要求：Ubuntu 22.04 / 24.04 amd64，Python 3.10+、curl、系统 CA、sudo 与真实 systemd。Ubuntu 26.04 暂不支持，未知版本同样拒绝。
脚本向导重新打开 `/dev/tty`，不会把管道 EOF 当成用户批准；无 TTY 的自动下载验签使用单独
`--download-only`，它只运行只读 plan，不能混用 `--apply` / `--start`。
首次命令默认显示计划；依赖安装、数据库 / libvirt 准备和最终应用 / 启动均需明确选择。
“一个入口”不等于省略真实 TLS、独立 DB、节点身份、镜像、资源预算和安全审批。

主控与被控是不同机器上的不同角色；不要把节点装到现有 1GB 财务测试机。
详细操作与恢复见[安装说明](../deploy/install/README.md)。

## 先验证，后执行

1. 只从固定 GitHub 仓库和固定 tag 读取公开 HTTPS 元数据，核对仓库 / owner 数字 ID、默认 main、
   prerelease 状态、tag 的精确 commit，以及完整且无重复的资产列表。下载限制 HTTPS、重定向主机、大小和时限。
2. 验证器使用固定版本 `gh 2.103.2`，其完整官方 tar 与单个 binary 都有源码固定 SHA / 大小；
   只读取唯一预期 binary 到 root 私有缓存，不全量解包，不安装全局 CLI，不读取用户 token / gh 配置。
   Sigstore trust root 同样固定 SHA / 大小，不在验签时刷新 TUF。
3. 通过实际 Sigstore proof 检查固定 Actions workflow、GitHub OIDC issuer、公开仓库与 owner 数字 ID、
   GitHub-hosted runner、`refs/heads/main`、source / signer digest 和透明日志时间证据。
   认证 certificate 与 statement 的精确 asset 名称、SHA；仅靠 provenance 中的自报字段不足以授权。
4. 签名清单绑定版本、源码 SHA、所有 payload 的名字 / 大小 / 哈希。先认证 capsule，核对其完整三文件
   `install.py`、`provision.py`、`release_verify.py`，再允许 Python 导入或执行；未知邻接文件也拒绝。
5. 本地 root 私有 receipt 记录路径与来源，每次生产 installer 使用时**重新读取真实字节与复验签名**。
   不接受 `verified:true`、外部 checksum 或 JSON 声明替代密码学证明。`--allow-development` 不能授权 release 包。

Release ID 在 build 签名前尚不存在，因此只是本次从 GitHub HTTPS 观察并固定的元数据，
用于检测下载期间的 Release / 资产变化，**不是 build 签名的授权来源**。授权来源是固定 builder 身份、
精确 source SHA、签名清单与实际制品字节。初始脚本审核与后续资产签名是两层不同信任，不能混说。

生产 `install.py --plan --release-receipt ...` 是离线只读，不下载、不修改宿主、不生成 pycache。
bootstrap 首次下载会创建 root 私有缓存，这不等于安装软件 / 服务。
下载和验证失败保留明确错误，不回退演示、开发包、过期签名或“不安全继续”。

## 构建、签名、发布分权

- 只在 main 手动发起独立 build workflow；指定 Cloud tag 必须指向当前 workflow 的精确源码 SHA。
- 要求同 SHA 的财务与 Cloud 回归，加上 Ubuntu22/24 两套 native libvirt 门禁，共 16 项发布前检查（Cloud 11 + 财务 5）。
  财务独立 `Real MySQL financial browser acceptance` 与 `Native financial acceptance (ubuntu-22.04)` 均须实际成功，演示数据或24检查不可替代。
  两个必需工作流在每次main push调度，不按改动路径过滤；财务或文档单独变更也必须取得同SHA的完整证据，不能用手动run或旧SHA补位。
  后续发布 / 下载 job 不混入这16项，不能用旧提交或只有 workflow 总结替代每项结论。
  这是用户批准的支持范围收敛，不是降低 22/24 的门槛；历史 14/15 失败结果保持原样，必须重跑新精确提交。
- 从同一 Git commit 快照构建两次实际静态 Go 二进制与 Vue UI，并比较完整归档字节。无 prebuilt / fake-build 发布入口。
- build 不持有 write / OIDC 权限；独立 attest job 只为通过固定策略的数据签名；publisher 使用受信 main 策略验证
  精确来源、签名与资产后才获得发布写入。不能先执行下载候选中的 installer 来“验证”自己。
- 仅创建新的 draft、上传精确资产并核对，最后公开为 prerelease、`make_latest=false`。
  既有 tag / Release / asset 碰撞拒绝，不 `--clobber`，不改仓库全局设置。
- 发布后在两套独立 runner 上匿名下载 controller / node，通过真实验签并运行认证后的生产只读 plan。
  两者成功才算下载链验收；单纯 push tag / 创建 Release 不等于完成。

资产包括两个角色包、installer capsule、bootstrap、`SHA256SUMS`、`release-manifest.json`、
`provenance.json`、固定 `release-trusted-root.json` 与 `attestations.jsonl`。checksum 是完整性工具，
只有与签名清单和受认证来源一起使用才构成此通道的身份验证。

## 已覆盖与仍待验收

Ubuntu 官方镜像验证与 TCG 测试见[原生 libvirt 门禁](../deploy/ci/libvirt-native.md)。它真实执行
APT / systemd / libvirt，检查默认网络未启动、专属 Unix socket / mount namespace、宿主网络不变，
并要求真实 node doctor 因缺少 KVM 拒绝就绪。**TCG 不是 KVM 真机**。

同提交实库 / 浏览器、依赖扫描与下载签名结果分别保留证据。仍需专用 KVM 宿主进行客户 VM 创建 / 电源 /
快照 / 备份 / 冷迁移、OVS/VPC/公网真实包流、限速、重启/断电恢复和整机安装升级恢复验收。
主控新 MySQL 的完整生产 bootstrap / TLS / systemd 安装也不能由单独 SQL grants 测试替代。
所有结果绑定精确 SHA，见[验证入口](VALIDATION.md)。

当前必需集合为Cloud11门、财务5门，共16门；财务新增明确命名的
`Native financial acceptance (ubuntu-22.04)`，原`checks`仍保留Ubuntu24。
两套策略拒绝缺失、跳过、失败或demo替代。历史15门通过记录仍只属于当时SHA，不能冒充新集合成功。

参考：[GitHub attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)、
[`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify)、
[libvirtd 默认 Unix / socket activation](https://libvirt.org/manpages/libvirtd.html)。
