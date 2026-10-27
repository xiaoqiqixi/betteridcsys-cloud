# 星屿云 · 主控与 KVM 被控

独立云主控、Vue 管理台及 Linux KVM 计算节点。主控负责权限、资源任务和状态；被控通过 libvirt/QEMU 管理虚拟机、存储和受限网络动作。

[财务前端](https://github.com/xiaoqiqixi/betteridcsys-frontend) · [财务后端](https://github.com/xiaoqiqixi/betteridcsys-backend) · [主控与被控](https://github.com/xiaoqiqixi/betteridcsys-cloud)

## 目录

| 目录 | 内容 |
| --- | --- |
| `aster-cloud/cmd/` | 主控、被控、网络工具和显式财务连接器 |
| `aster-cloud/internal/` | 实例/节点、任务、权限、快照备份、冷迁移、VPC/OVS/NAT/公网 IP |
| `aster-cloud/frontend/` | 主控管理 UI，不复用财务门户的布局 |
| `aster-cloud/deploy/` | 原生安装器、systemd、运维和验收工具 |
| `contracts/billing/` | 最小财务↔主控协议 SDK；没有财务账本、数据库或支付实现 |

版本代码基线 0.1.0-rc.1，主控 schema12。目标 Ubuntu22.04 / 24.04 amd64，不使用 Docker。热迁移、HA、完整安全组、IPv6 和受控 VNC 等仍有缺口；真实 KVM、跨节点物理网络与生产容量验收后置，不能宣称生产可用。

## 构建

```sh
python3 scripts/verify-billing-contract.py
cd aster-cloud
go mod download
go test -mod=readonly -race -count=1 ./...
go vet -mod=readonly ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false ./cmd/aster-controller ./cmd/aster-node ./cmd/aster-network ./cmd/aster-billing-plugin
cd frontend
npm ci
npm run typecheck
npm test
npm run build
npm run format:check
```

没有显式隔离 MySQL、分发版 OVS/libvirt 工具或宿主权限时，相关测试会跳过；只算对应 unit/build，不算真机或全链验收。当前 CI 名称区分这些范围，不用绿色构建替代真实 KVM。

SDK按原提交的文件摘要校验，Go依赖在本仓库内闭合，不需要原仓库或财务服务端源码才能编译。接口变化需要显式更新 SDK 与兼容测试，不改金融金额、支付或历史快照。

[完整能力与限制](aster-cloud/docs/ARCHITECTURE.md) · [主控使用](aster-cloud/docs/GETTING_STARTED.md) · [节点操作](aster-cloud/NODE_README.md)

## 下载与安装

复制的旧安装器仍固定原发行者身份；新仓库首版通道须独立绑定新仓库 ID、工作流身份、签名与产物。源码存在不等于本仓库已有可执行的一键安装入口。迁移验收前不改弱来源保护，也不移除原下载通道。

## 拆分与交付状态

本仓库从已提交、通过原项目 CI 的 main `fa4d2139ff5ecfc2802c0825e839134ca488d138` 拆出，不包含原工作区未完成的 schema14/员工权限改动。保留 Apache-2.0 许可证；初始来源见 [SOURCE_ORIGIN.json](SOURCE_ORIGIN.json)。它是来源清单，不是发行签名或本仓库的验收证明。

只使用 `main` 分支，不导入旧 Git 历史、贡献者署名或旧标签。原仓库 CI 结果不自动继承；本仓库构建与验收以自己的提交和运行记录为准。

三个新仓库均完成构建、首版 Release、匿名产物下载/校验和安装更新来源迁移后，才删除原仓库及其 Releases。未完成迁移门禁时不得删除；具体门禁见 [仓库迁移清单](MIGRATION.md)。
