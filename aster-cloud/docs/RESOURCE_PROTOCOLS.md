# `aster.resource/1` 的两个协议上下文

`aster.resource/1` 在云主控和财务插件中沿用了相同字符串，但表示两份不同合同。客户端必须同时识别通信方式、端点、认证和消息结构；不能仅凭 `protocol` 字符串选择解析器或授权。这里保留既有 wire identifier，不重命名协议。

| 上下文 | 通信与认证 | 消息及能力 |
| --- | --- | --- |
| 云主控 HTTP 资源视图 | HTTPS GET `/v1/resources/{resource_id}`；billing Bearer token，加唯一 `X-Aster-Owner-Ref`，精确绑定资源与 owner | 响应 `protocol` 为 `aster.resource/1`，提供单个资源的只读观察；不执行开通或生命周期写操作 |
| 财务资源插件 RPC | 财务 host 与 `resource.aster-cloud` worker 的 Unix socket RPC；由插件管理器审批 manifest/摘要/能力，握手绑定 nonce 与同一物理连接，校验 peer UID | 协议名为 `aster.resource/1`，封装 send 或 lookup；用 base64 外封套携带既有 canonical `aster.controller/1` 请求/结果字节 |

HTTP 资源视图的 JSON 字段固定为：`protocol`、`resource_id`、`owner_ref`、`hostname`、`state`、`node_id`、`resources`、`updated_at`。它没有插件握手或 RPC 外封套；admin-read/admin-write 不能代替 billing token，Console 用户 ID 也不是财务 owner。POST 等写方法被拒绝。实现与边界测试见 [resource_view.go](../internal/control/resource_view.go) 和 [resource_view_test.go](../internal/control/resource_view_test.go)。

插件 RPC 的 send/lookup 服务于财务原有持久开通与核对流程。worker 向云主控提交的开通合同仍是 `aster.controller/1`（原八字段请求、六字段结果）；send 不是读取上述 HTTP 资源视图，lookup 也不能被理解为任意资源查询。插件选择、审批、凭据和握手不会因 HTTP 返回同名 `protocol` 就自动成立；主控也不会把 HTTP body 当插件命令执行。插件的完整合同见财务项目的 [RESOURCE_PLUGINS.md](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RESOURCE_PLUGINS.md)。

独立 `aster-billing-plugin` CLI 又是另一种交付方式：它使用 `aster.controller/1`，不由财务 runtime-plugin manager 加载，也不与上述两个 `aster.resource/1` 上下文互换。见 [财务适配器说明](../plugins/billingconnector/README.md)。
