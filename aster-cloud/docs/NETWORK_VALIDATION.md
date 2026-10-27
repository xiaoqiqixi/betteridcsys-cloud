# 网络/IPAM、OVS 与财务适配开发验证

2026-10-23。以 `e47c79d387651bc07da70731bafddabcd4fbd0fe` 为基线，仅更新 main。没有创建标签、发布主控正式 Release、升级现有财务站或安装 OVS/libvirt。本记录是开发检查，不是完整 KVM 加强版验收。

## 已实现与未接通的边界

- 主控新增 migration 005、VPC/IPv4 地址池/地址预留及真实会话管理 API、分页管理页、权限和事务审计。完整意图/actor/kind 幂等，节点与地址双重唯一；并发最后一个地址只分配一次。`planned/reserved` 不冒充已联网，未确认解绑不会自动回收。
- 被控新增独立 `aster-network plan/apply/status/verify`：root 审批专用整桥、静态单节点 VPC metadata 隔离、精确 IP/MAC/ARP、双向按 IP drop meter、写前 journal、未知结果保留、flow/meter/身份读回。`verify` 只读实时核对，历史 applied 回执不能替代它。此模块没有接入现有 VM 创建/开机链，也不提供路由/NAT/DHCP/跨节点。
- `aster-billing-plugin` 是显式宿主资源适配器，复用原 `aster.controller/1` 商品快照摘要、operation/order 及六字段结果；不是支付渠道或 runtime-plugin manager 插件，不替代财务已有持久开通任务。财务只有新增公开 transport 包装及测试，金额、币种、支付、幂等和历史快照逻辑未改。
- 实例只读 metrics 链及页面已补齐。所有计数为 uint64 十进制字符串或 null；不伪造内存使用率、周期流量或财务扣费。

详细功能差距见 [KVM 加强版矩阵](KVM_ENHANCED_PARITY.md)、[网络 API](NETWORK_API.md)、[OVS 执行器](../internal/fabric/README.md) 和 [财务适配说明](../plugins/billingconnector/README.md)。

## 冻结源码的检查

| 检查 | 实际结果与限制 |
| --- | --- |
| Go1.27.3 / Darwin arm64 全 scope race | **906 PASS 测试事件、0 FAIL/race**；22 个测试事件明确 SKIP：21 个缺 DSN 的入口/子项及 1 个要求真实 root policy 的 TLS 入口。没有将这些跳过算作本机实库成功。 |
| Go 静态检查/构建 | vet、固定 actionlint1.7.7、shell 语法及 diff-check 通过；CGO=0/Linux amd64 的 controller、node、network、billing-plugin 四程序构建通过。 |
| 财务旧合同/传输回归 | Go1.27.3 race：49 PASS 事件、0 SKIP/FAIL；覆盖原请求、结果和固定目的地传输。与全 scope 合同覆盖可能重叠，不合并数量。 |
| 管理台 | 545 Vitest 用例 /15 文件，0 SKIP/FAIL；typecheck、Prettier check、production build 通过。**不是本轮浏览器或手机视觉验收。** |
| 依赖扫描 | npm 全依赖扫描 0 漏洞；Go1.27.3 + govulncheck1.9.0 报未发现漏洞。先前本机 Go1.26.4 命中 17 个可达标准库漏洞，失败日志保留；改用与 CI 相同的独立工具链重新测试/构建/扫描，没有忽略告警或删除门禁。 |

Go 源文件/SQL/合同 manifest 逐文件留存；CI 夹具修正后全量重跑对应 SHA256 为 `5afe0c6ea9616624b4eb4ddbbf9ad4eb0c8eaf672e5831713dbd4bdd2fe199a9`。前端 58 个 src/tests 文件冻结 manifest SHA 为 `3ce04deb1daa573cc968b3d19a3c65d67fb7c01a884ccaa7ecf741b9c9fa3096`。Go 的 CI 修正只改测试；前端最终另修复了下述路由失效问题，构建资产已重新生成。

最终前端构建为 `index-BsxKwddS.js` / `index-DbXj-mn0.css`，HTML SHA256 `e67ddf74aa3141480b728c811d2de09bd76d57601dd5c1e12be97684f4f1d0ed`。这些是本轮开发构建，不作为财务 Release 资产上传。

## Ubuntu22 真实隔离 MySQL / TLS

在现有 Ubuntu22 测试机另启原生 MySQL8.4.13，仅私有 Unix socket、禁止网络监听、MemoryMax=256MiB；各测试创建并删除自己随机命名的 `_test` 数据库，没有连接财务库。

| 测试 binary | 结果 | SHA256 |
| --- | --- | --- |
| 控制器（含 schema 5、metrics、网络 Console wiring） | 320 PASS 事件，0 SKIP/FAIL | `5ecb65d80eefdea57bc1de36c82c7809acce496cc8fe5cdd828701fb29dfcd2c` |
| 身份/会话/RBAC（最终 schema 5） | 27 PASS 事件，0 SKIP/FAIL | `768a3291f7c5bc6cd104cb10455769c26d631969ec9c8d1ab991b22e676e5cd8` |
| 网络/IPAM | 73 PASS 事件，0 SKIP/FAIL | `b9a79a8d14b54f7d26a3ce6691b506099e63a5efc13b4bc1b25f2731d7069321` |
| root 保护策略 + 实际 HTTPS 适配器 | 16 PASS 事件，0 SKIP/FAIL | `756f72f1ff3ea0dd1de6671b97e061601855cdb584cd7d4091c2d36762a763e3` |

这些远端测试 binary 由 Go1.26.4 交叉编译，**不是 race binary 或安装产物**。源码在后续 Go1.27.3 上完成全量 race/构建/扫描；最终 GitHub CI 另在 Go1.27.3 上运行实库 race，不套用旧提交的 Actions 成功。

实库覆盖持久化/完整意图重放/跨 actor 冲突、最后地址并发、跨池重复地址、禁用池/错误实例归属/已删除实例、schema 形状冲突、真实 TLS Cookie/CSRF/逐方法权限和原 ID 查询。TLS 适配器测试覆盖原始绑定、409、错误 order/digest、重复/额外字段、重定向、断线、超大回包与不受信 CA；控制器响应为合同替身，不是实际 VM。

一次 SSH 网络波动截断上传，未执行残缺 binary；重新传输并核对 SHA 后执行。测试已完成但 SSH 丢失响应的 networking 日志从专用目录取回核对，不把网络故障算作产品失败或跳过成功。

## 本轮修复的实际问题

- libvirt8 `domstats --raw` 字符串实际可不带引号，修正 parser/夹具；guest balloon-unused 没有新鲜 last-update 则返回 null。
- 网络创建的部分意图不再误清 pending；池地址次序变化不会产生第二次 POST；过时页面/会话/权限回包和异步 hash 间隙不能确认旧请求；非 201、重放标记或无效 cursor 不冒充首次成功。
- 新导航入口对应的旧测试夹具补齐第 6 路由；没有删测试、放宽权限或改变生产协议来通过。
- OVS `verify` 拒绝历史未决记录、缺失/被替换 desired 文件、丢失/漂移 flow、meter、端口身份；只读命令另有白名单。独立代码复核和初版 150 个 fabric/CLI race 事件通过，后续新增 4 个跨平台临时目录事件，共 154 个，包含在上述全量，不重复累加。

### 首次 GitHub CI 暴露并修正的夹具问题

提交 `8fe75d9` 的 [cloud CI 39932042264](https://github.com/xiaoqiqixi/betteridcsys/actions/runs/39932042264) **失败**，不标成全绿：fabric 夹具写死 macOS `/private/tmp`，Ubuntu22/24 与原生实库 job 无该目录；一个旧迁移确认用例在 native WebCrypto digest 尚未完成时就查询错误提示。修正为 `t.TempDir()` + `EvalSymlinks`，保留真实祖先/权限校验，新增默认 Linux `/tmp` 与 symlink TMPDIR 回归；前端用可控 deferred 实证 digest 未完成的 busy 状态，释放真实 digest 后等待确定 UI 终态，仍断言只有一次 POST。没有新建系统目录、改生产安全函数、加任意 sleep、放宽协议或删除用例。

修正后重新执行上述 906 Go race 和 540 前端用例；最终 GitHub 结果须按后续 main 提交单独核对，不能用本机通过覆盖这次失败。

### 第二次 GitHub CI 暴露并修正的取消时序问题

提交 `037e77f` 的 [cloud CI 39932974414](https://github.com/xiaoqiqixi/betteridcsys/actions/runs/39932974414) 中，Ubuntu22/24 单测构建及管理台检查通过，实库 job 在既有 hypervisor 取消时序测试失败：夹具把所有 virsh 命令都阻塞，Shutdown 可能落在只读 ownership 预检，此时生产逻辑正确返回 `LIVE_OWNERSHIP_UNCONFIRMED`，并非测试预期的“电源命令已发出但结果不明”。

仅修改测试夹具，精确阻塞 `destroy`，用 channel 握手确认已通过 `dumpxml` / `domstate` 并进入变更命令后才取消；加强为同时核对 `uncertain` 与 `POWER_OUTCOME_UNCERTAIN`。保留持久化隔离、进程重启、其他动作受阻以及不能自动重发 destroy 的断言。没有 sleep、重试生产操作或放宽结果。确定性预检复现、定向 race 连跑 100 次、完整 hypervisor race、vet 及修正后的全量 906 PASS / 22 SKIP / 0 FAIL 均留存。本机 22 项跳过边界仍如上，不替代最终 GitHub 实库零跳过门禁。

### 已通过的主控 CI 与最后路由回归

提交 `31f4ab8` 的 [cloud CI 39934631704](https://github.com/xiaoqiqixi/betteridcsys/actions/runs/39934631704) 四项 job 全部通过：Ubuntu22/24 单测与构建、管理台检查、原生隔离 MySQL 与 root TLS / Go 扫描。实库 job 无 SKIP；这不替代真实 KVM/OVS 或新管理台浏览器验收。

随后只读复核发现 Vue Router 复用 `/networks/:kind` 页面时，打开中的创建弹窗没有随 route 失效。已同步监听真实 `route.fullPath` 关闭旧弹窗，使旧 generation 失效并保留原 pending。新增 5 个 memory / WebHashHistory 情境，明确断言同 route record、同组件 UID，覆盖分类/分页变化、迟到成功与断连失败：POST 始终一次，迟到响应不清 pending、不通知或刷新新页；回原表单后只 GET 原 ID 才核对完成。最终 545 用例、typecheck、格式检查、build 通过。WebHashHistory 在 JSDOM 内运行，不冒充真实浏览器。该后续 main 的 GitHub 结果另行核对，不借用 `31f4ab8` 的通过状态。

初次提交的 [性能基线 39932042358](https://github.com/xiaoqiqixi/betteridcsys/actions/runs/39932042358) 在 runner 下载 Ubuntu 包/字体时耗尽 25 分钟，测量步骤未执行；完整日志保留，不能写成性能通过。这不是主控实库失败，也没有通过改超时、换不可信源或跳过校验规避。

## 清理与明确未验证项

已停止本轮独立 MySQL，删除专用目录、临时数据库、随机 DSN/配置和上传程序，关闭 SSH master；财务 API、edge、原 MySQL 三服务仍 active。本轮没有创建 CA、改钥匙串、改宿主网络或重启财务服务。

**没有完成**：真实 OVS 包隔离/吞吐/重启故障、KVM guest 启动与 SSH、DB→fabric→VM 网络门禁、路由 VPC/网关/NAT/DHCP/IPv6/跨节点私网/浮动 IP、实际磁盘恢复与双宿主迁移、主控原生安装/备份恢复/回滚、这一批新页面的真实手机/桌面浏览器截图。旧截图不充当新页面证据。新增 schema 5 不能仅替换旧 binary 回滚，见 [运维说明](../deploy/controller-OPERATIONS.md)。

原始结果、初次失败、源码冻结清单、构建 SHA 及清理回执保存在 ignored `aster-cloud/artifacts/kvm-enhanced-20261023/`。main 推送及 CI 只证明相应开发检查，**不代表完整加强版已交付或可以上架出售**。
