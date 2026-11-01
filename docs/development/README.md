# 云系统开发与发布指南

[使用文档](../README.md)

## 源码与接口

`aster-cloud/` 是主控与节点 Go 模块；`aster-cloud/frontend/` 是管理台；`contracts/billing/` 是最小财务协议 SDK。SDK 来源由[校验工具](../../scripts/verify-billing-contract.py)核验，不能把整个财务服务端带入云系统依赖。

[管理台合同](../../aster-cloud/docs/CONSOLE_API.md) · [网络合同](../../aster-cloud/docs/NETWORK_API.md) · [节点与网络设计](../../aster-cloud/docs/OVERLAY_CONTROL.md)

## 验证与发布

开发检查见下方“本地构建与测试”。[独立仓库 CI](../../.github/workflows/ci.yml)定义 8 组任务，矩阵展开后共 **18 项任务**：

| Job ID | 数量 | 覆盖范围 |
| --- | ---: | --- |
| `go-unit` | 2 | Ubuntu 22.04/24.04：Go race、vet、构建、最小财务 SDK、部署工具与安全合同 |
| `frontend` | 1 | Vue 类型、单测、构建、格式与依赖检查 |
| `native-libvirt` | 2 | Ubuntu 22.04/24.04 签名 guest 中的 libvirt 软件准备 |
| `native-controller-provision` | 6 | Ubuntu 22.04/24.04 各运行 restore-data、restore-sessions、restore-configuration 三种场景 |
| `native-ovs-parser` | 2 | Ubuntu 22.04/24.04 原生 OVS 解析与编码 |
| `native-nat` | 2 | Ubuntu 22.04/24.04 隔离网络命名空间中的 NAT 报文与撤销 |
| `native-mysql` | 2 | Ubuntu 22.04/24.04 独立 MySQL、race、静态构建与漏洞检查 |
| `network-browser` | 1 | 真实后端、独立 MySQL 与严格 TLS 浏览器回归 |

main push、同仓库 PR 和手动触发均运行全部 18 项；fork PR 运行两项 Go 检查与一项前端检查，原生/浏览器任务按 job 条件干净跳过。当前 workflow 不使用仓库 secrets，权限固定为 `contents: read`；未来依赖 secrets 的任务也必须保留同仓库门禁。PR 使用普通 `pull_request`，不使用 `pull_request_target` 执行提交代码。concurrency 为 main 的每个提交按 SHA 分组，保留完整运行；其他 ref 按 ref 分组，后续提交取消同组旧运行。必须核对同一提交的实际结果，不能把任务已配置视为验收通过。

主控实库与浏览器任务使用云仓库自己的[隔离 MySQL 测试环境](../../aster-cloud/deploy/ci/native-mysql/README.md)，不需要检出财务实现。浏览器使用临时 Firefox 配置和独立测试 CA，结束后清理，不修改开发者或生产主机的证书信任。

libvirt 准备任务运行签名 Ubuntu 镜像中的真实 APT/systemd；使用 TCG，明确验证没有 KVM 时被控拒绝就绪。OVS 解析与隔离 NAT 报文测试不等于真实宿主、物理网络或跨节点 KVM 验收。新仓库正式发行来源迁移也仍是独立门禁。

原生与浏览器证据名称绑定运行 ID 和 attempt，明确禁止覆盖。重跑不能删除或替换失败轮次的证据；核验时需匹配实际提交与轮次，而不是取同名文件的最新一份。[GitHub 上传制品规则](https://github.com/actions/upload-artifact#not-uploading-to-the-same-artifact)

- [验证记录](../../aster-cloud/docs/VALIDATION.md) · [浏览器验证](../../aster-cloud/docs/BROWSER_VALIDATION.md)
- [安装验证](../../aster-cloud/docs/INSTALL_VALIDATION.md) · [发布通道](../../aster-cloud/docs/RELEASE_CHANNEL.md)
- [内置升级方案](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/docs/development/BUILTIN_UPGRADES.md)：主控维护升级、被控滚动升级、兼容与失败恢复的开发合同，尚非发布功能。
- [KVM 功能对照](../../aster-cloud/docs/KVM_ENHANCED_PARITY.md)：后续工作与明确未验收项。
- [统一安装与主控迁移](INSTALL_AND_MIGRATION.md)：单入口角色选择、完整迁出/恢复/接管/回退合同与分阶段验收；迁移不是只上传数据库，也不等于已有 VM 冷迁移。

## 工程记录

[仓库迁移](REPOSITORY_MIGRATION.md) · [初始文件来源](../../SOURCE_ORIGIN.json) · [协议 SDK 来源](../../contracts/README.md)

## 本地构建与测试

Go 模块、前端与部署工具位于 `aster-cloud/`；`contracts/billing/` 仅包含财务通信协议 SDK，不包含财务服务端。

```sh
python3 scripts/verify-billing-contract.py
cd aster-cloud
go mod download
go test -mod=readonly -race -count=1 ./...
go vet -mod=readonly ./...
go build -mod=readonly ./cmd/aster-controller ./cmd/aster-node ./cmd/aster-network ./cmd/aster-billing-plugin
cd frontend
npm ci
npm run typecheck
npm test
npm run build
npm run format:check
```

开发工具使用 Go 1.27.3、Node.js 24.19.0。实库与宿主工具测试需要隔离环境；未配置环境而跳过的测试不能代表对应功能通过。真实宿主机测试应在独立环境执行。
