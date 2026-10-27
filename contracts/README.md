# 财务↔主控协议 SDK

`billing/`仅含原项目公开 `controllerapi` 与其内部 wire/HTTPS 实现及测试，共八个 Go 文件，标准库依赖。不是财务后端副本，不含订单持久化、金额计算或支付实现。

来源提交和逐文件 SHA256 见 `billing/UPSTREAM.json`。主控的 Go replace 指向本地最小 SDK，独立克隆即可构建；以后协议变更需同时更新兼容测试与固定摘要，不能从可变 main 静默下载执行。
