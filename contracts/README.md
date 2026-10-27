# 财务↔主控协议 SDK

`billing/`仅含原项目公开 `controllerapi` 与其内部 wire/HTTPS 实现及测试，共八个 Go 文件，标准库依赖。不是财务后端副本，不含订单持久化、金额计算或支付实现。

来源提交和逐文件 SHA256 见 `billing/UPSTREAM.json`。主控的 Go replace 指向本地最小 SDK，独立克隆即可构建；以后协议变更需同时更新兼容测试与固定摘要，不能从可变 main 静默下载执行。

根目录 `go.work` 只声明主控和本 SDK 两个源码模块。SDK 不伪装成已经下载的第三方归档：本地源码由逐文件摘要与实际测试核验，第三方模块仍先下载再执行 `go mod verify`，不关闭 checksum database、不删除依赖验证。首次新仓库 CI 实际暴露的 local-replace/ziphash 失败已据此修正；不是靠重试或忽略错误。

[Go 官方模块验证说明](https://go.dev/ref/mod#go-mod-verify)说明，`go mod verify` 检查模块缓存而非本地源码的发行者身份。生产安装包来源与签名仍须独立完成，workspace 不能替代发行验收。
