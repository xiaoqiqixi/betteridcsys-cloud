# 任务定位、审计筛选与运行日志增量验收

2026-10-23，基于 main `54816288611b5a7dcc00c2d4b72f07d3b4bd167a` 的后续开发。不创建新分支、标签或主控正式 Release，不改变财务安装包、现有测试站和财务后端。

## 实现范围

- 资源操作列表按原任务 ID 定位，并提供独立详情；实例及创建/动作/迁移弹窗可直达同一任务。详情展示公开状态，不输出保存的请求、宿主路径或凭据。它查询 `controller_operations`，不冒充旧财务 `controller_jobs` 的统一任务中心。
- 派发和核对仍需对应动作权限与明确确认。读取状态只 GET；丢 ACK 不自动重发。创建者与本次派发人分开，已知任务绑定 ID、动作、实例、节点、制品、目标节点及创建者。
- 修复 operator 派发 admin 创建的任务后丢 ACK 时，旧 pending 错按创建者清理而残留的问题。完整绑定和前进状态可解除相应未知记录；合法 `202 accepted`、旧版本无绑定记录、错绑定及跨身份迟到响应不能解除或自动重发。64 条上限不通过驱逐未知任务绕过。
- 详情内的“读取原任务”使用受控 GET，验证成功才关闭弹层；失败保留原编号。兼容尾斜杠和编码后的同一任务地址，避免自链无效，异页导航仍用 replace。浏览器不能读取或持久保存 pending 时拒绝发送写请求；清理保存失败则保留原未知记录，不在当前页或刷新后自动重发。
- 审计支持事件类别、动作、操作者、对象和时间范围的 AND 精确筛选；每页 100 条，游标绑定筛选条件。非法参数不退回全量查询，失败不画成空结果。页面条件写入 URL，返回可恢复。
- 迁移 004 添加两类审计表的六个查询索引。部分 DDL 中断后，只有定义完全相同的既有索引可以安全重入；冲突拒绝，不删除或重建已有索引，不改 001–003。
- 主控/被控 stderr 使用 UTC JSON 白名单诊断事件；未知结果、journal 未确认及转运异常用 WARN。正常 CLI stdout 合同不变。诊断不代替事务审计或恢复 journal，也不根据日志推进状态。
- systemd 模板添加明确日志目的地和逐 unit 限流；独立 journald 保留上限仅提供可审核模板，本轮未安装或启用。

## 验证范围与记账

本地未配置 DSN 的 SKIP、Ubuntu22 真实 MySQL、组件测试和实际浏览器分别报告，不相加宣传独立场景数量。

| 最终源码检查 | 实际结果 |
| --- | --- |
| Darwin arm64 / Go1.26.4 `go test -mod=readonly -race -count=1 -v -timeout=10m ./...` | 450 PASS 事件，15 个缺少 DSN 的入口/子场景明确 SKIP，0 FAIL / race warning |
| `go vet -mod=readonly ./...`、actionlint1.7.7 | 通过 |
| Linux amd64 / CGO=0 两个服务程序构建 | 通过，不表示已安装运行 |
| Ubuntu22 私有 MySQL8.4.13，最终 control 测试程序 | 295 PASS 事件，0 SKIP / FAIL |
| 同一实库 identity 测试程序 | 27 PASS 事件，0 SKIP / FAIL |
| 主控 Vue / TypeScript | 最终 314 Vitest / 9 文件，0 SKIP / FAIL；typecheck、format、production build 通过 |
| 财务 controllerapi / internal/controllers race 回归 | 48 PASS 事件，0 SKIP / FAIL / race；不是完整财务发行验收 |
| 主控前端全依赖 `npm audit --audit-level=high` | 本次查询 0 漏洞；不代表 Go 或全产品无安全风险 |

上述 Ubuntu22 control 测试 binary SHA256 为 `7a5966cf82ae28194d32ce45bd1ada69028a672f6f7fb776ee3129168eca07d0`，identity 为 `855ffb065fd41f36c8713a2b9c369f456cbb5d615cb2ad41c352245de9f327e2`；不是 race binary。最终静态主控 binary 为 `f6ebc31815ed1e675effc5da722101aa2d2ada62cc031060fa5e663899224c3a`，被控为 `b6462b990777e2c89164e13c6fbbe098008d00c4c3f84e036e2690c9aba79b25`。前端最终构建为 `index-BcJUyobB.js` / `index-BlQ60jzN.css`，不沿用修复前的 248 测试结果。

本轮 Ubuntu22 使用独立 Unix-socket MySQL8.4.13、隔离库 `aster_cloud_browser_test`、私有配置及 256MiB 内存上限。财务三个服务未停止、升级或改库。实库测试包括 HTTPS/Cookie/CSRF/RBAC、精确筛选/时间边界/大小写、跨来源稳定分页、六条索引 EXPLAIN、十五张表的只读校验、004 部分 DDL 重入和冲突拒绝。节点执行器仍为受控替身，不是实际 VM。

`systemd-analyze verify` 在 Ubuntu22 / systemd249 上通过：只验证临时副本，把 ExecStart 换成 `/usr/bin/true`，未安装或启动服务。这不是原生安装、TLS 配置或升级回滚验收。

原始日志与测试 binary SHA 保存在 ignored `aster-cloud/artifacts/operations-20261023/`，不作为安装资产发布。

## 浏览器和环境安全

本轮新增任务详情和审计筛选尚未执行实际桌面/手机浏览器回归，不能沿用 2026-10-22 截图或把组件测试称作视觉验收。本轮临时 localhost CA 尚未授权及创建，没有通过关闭证书检查绕过此项。

上一轮两枚测试 CA 已核对从用户钥匙串移除、无残留信任设置，旧 localhost 证书验证返回不受信任；旧测试私钥和凭据亦已删除。本轮私有 MySQL 已停止，仅本轮拥有的测试目录、库与凭据已删除，SSH 复用连接与 IPv4/IPv6 的 5445 转发已关闭；9445 未启动 API。清理后既有财务 API、edge 和 MySQL 三服务均为 active。

## 升级与回退限制

升级前须停写并备份**独立主控库**，使用匹配源码、前端及节点 journal 格式。迁移 004 执行并确认之后，schema 仅认识前三版的旧 binary 会拒绝检查；**不能只换回旧 binary 就声称回滚成功**。不要删除迁移记录、伪造 SHA 或手工删索引降级。

需要回退时，先停主控写入，保留节点恢复 journal、磁盘、制品和 source fence，再根据已演练的配套版本及升级前独立库备份恢复。备份后的资源操作必须逐一核对，不能恢复数据库后自动重派；本轮没有进行这项生产恢复演练。不回退财务库，不修改历史订单或商品快照。

## 仍未验收 / 未交付

没有真实 KVM/libvirt VM、实际快照恢复、跨物理宿主迁移、网络/guest SSH、磁盘满/断电恢复、主控生产 systemd/Nginx/TLS 安装或完整升级/备份回滚演练。真实宿主验收按用户要求后置。

新增页面的手机/桌面效果、200% 缩放、软键盘、多浏览器、减少动态效果及浏览器故障注入尚未补验。未把此增量称为完整产品验收，也不发布独立主控正式 Release。

完整产品仍缺的 MFA/SSO、VNC、热迁移/HA、定时异地备份、数据盘/扩容、VPC/IPv6/计量、无 root API 分离及外部日志归档/告警等见 [功能矩阵](ARCHITECTURE.md)。
