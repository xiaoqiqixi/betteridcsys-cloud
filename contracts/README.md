# 财务↔主控协议 SDK

`billing/`仅含原项目公开 `controllerapi` 与其内部 wire/HTTPS 实现及测试，共八个 Go 文件，标准库依赖。不是财务后端副本，不含订单持久化、金额计算或支付实现。

来源提交和逐文件 SHA256 见 `billing/UPSTREAM.json`。主控的 Go replace 指向本地最小 SDK，独立克隆即可构建；以后协议变更需同时更新兼容测试与固定摘要，不能从可变 main 静默下载执行。

根目录 `go.work` 只声明主控和本 SDK 两个源码模块。SDK 不伪装成已经下载的第三方归档：本地源码由逐文件摘要与实际测试核验，第三方模块仍先下载再执行 `go mod verify`，不关闭 checksum database、不删除依赖验证。首次新仓库 CI 实际暴露的 local-replace/ziphash 失败已据此修正；不是靠重试或忽略错误。

[Go 官方模块验证说明](https://go.dev/ref/mod#go-mod-verify)说明，`go mod verify` 检查模块缓存而非本地源码的发行者身份。生产安装包来源与签名仍须独立完成，workspace 不能替代发行验收。

## 开通容量与永久拒绝（CL-1）

主控对两类情况使用不同结果，原售卖请求与摘要不变：

- 所有配置候选均要求托管直绑公网租约，而 billing 开通合同无法携带该租约：事务内持久化 `rejected`，原因 `DIRECT_PUBLIC_LEASE_REQUIRED`。没有匹配产品或健康候选明确不支持资源时，持久化 `UNSUPPORTED_PRODUCT`。相同 operation/order/摘要重放仍返回原拒绝，配置或容量变化不重新开通；更改请求返回冲突。
- 存在可用合同类型但节点无心跳、心跳过期、维护中、配置版本尚未同步或容量暂时耗尽：保持 HTTP 503 `NO_HEALTHY_CAPACITY`，不持久化拒绝或占用订单，财务可在条件恢复后重试原请求。混合候选中的暂不可观测节点也保留重试机会。

永久拒绝沿用固定 SDK 的 `status:"rejected"`、空 `resource_id`：POST/重放 HTTP 409，查询 HTTP 200。具体原因与拒绝一起存入主控 `controller_jobs.node_request` 的不可执行诊断记录，并追加 `provisioning.rejected.<CODE>` 审计。`node_id`、`instance_id` 和 node request SHA 均为空，不创建实例、租约或容量预留。`aster.controller/1` 的八字段请求、六字段结果保持逐字节不变，不增加原因码字段，本次不修改固定协议 SDK。原因码只保留在主控 job/审计中；后续由独立的 `aster.service/1` 协议承载，本次不接入该协议。
