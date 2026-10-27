# 财务资源适配器

这是独立、显式执行的资源开通适配器，复用现有 `aster.controller/1`。**不是支付渠道，不由当前财务插件管理器加载，不注册新的 runtime-plugin kind。** 不读写账单、金额、支付状态、服务记录或历史快照；不自动入账，也不自动重派。

## 与插件管理器资源 worker 的区别

本目录产物是独立 `aster-billing-plugin` CLI，manifest 的 `runtime_plugin=false`，
继续使用 `aster.controller/1` 的原商品/请求/六字段结果合同，不添加资源worker的 `core_min` 字段。

另一个产物 `resource.aster-cloud` worker **0.1.1** 位于财务项目，由插件管理器管理，
使用 `aster.resource/1`；其兼容声明为 **`core_min=0.5.10`、`core_max_exclusive=0.6.0`**。
Core **0.5.10** 已有独立正式发行，旧正式 **0.5.9** 二进制没有资源协议；资源 worker 本身仍为独立候选，不在 Core 六资产中。
不能把旧main版本字符串、CLI能调用HTTP或协议单测通过，当成旧正式包已能加载资源worker。
Core、plugin-host、plugin-manager 需来自支持协议的同一经核验版本；worker候选版本为0.1.1。
0.1.1区分于旧main本地0.1.0产物，避免修改manifest后同版不同哈希；旧目录不覆盖，包校验不放宽。
构建/安装和凭据隔离见[财务资源插件文档](https://github.com/xiaoqiqixi/betteridcsys-backend/blob/main/vps-billing/docs/RESOURCE_PLUGINS.md)。

## 优先使用现有财务原生链

当前财务系统已经可以直接对接主控 `/v1/provisioning`。后台商品保存 `disabled / preset / custom` 产品配置，订单保留配置历史快照，财务原生 provisioning 命令从已准备的持久任务读取不可变请求并管理 sending/uncertain 状态。该链无需本适配器即可运行。

本包用于需要独立 CLI 的 host 集成、兼容验证或第三方执行器。它是**无财务数据库状态的传输适配器**，不能代替财务原生持久任务与付款前置校验。调用方必须先持久保存原请求，再显式发送；本命令不会替调用方证明订单已付款。

## 构建及离线检查

在 `aster-cloud`：

```sh
go build -o ./bin/aster-billing-plugin ./cmd/aster-billing-plugin
./bin/aster-billing-plugin                 # help；不读 stdin、不联网
./bin/aster-billing-plugin manifest        # 能力清单；不联网
./bin/aster-billing-plugin validate-product < product.json
```

`validate-product` 只验证原公开商品协议并返回配置 SHA-256。它不验证远端套餐是否存在，也不声称节点支持配置中的全部能力。

例如非敏感 preset 配置（必须完整保留四字段）：

```json
{"mode":"preset","controller_id":"aster-main","remote_product_id":"small","resources":null}
```

custom 模式的 resources 也必须包含原协议全部 17 个字段。未知字段、缺字段、重复键、错误大小写、错误 null、数值类型及配置 hash 不匹配会被拒绝，不能夹带 URL、命令、token、宿主 root path 或财务字段。

## 固定主机策略

默认策略 `/etc/aster-billing-plugin/policy.json`，只允许 host 操作者通过 `--policy` 选另一个同样受保护的绝对路径；不从 stdin、商品配置或环境变量读取目的 URL。目录及策略、token、CA 由 root 管理，使用原财务 transport 的所有者、祖先目录、权限、symlink/hardlink、大小和文件稳定性检查。

策略格式沿用财务原生控制器策略：

```json
{
  "schema": 1,
  "controllers": [{
    "id": "aster-main",
    "enabled": false,
    "endpoint": "https://controller.example.invalid/v1/provisioning",
    "allowed_cidrs": ["192.0.2.0/24"],
    "token_file": "/etc/aster-billing-plugin/billing.token",
    "ca_file": "/etc/aster-billing-plugin/controller-ca.pem"
  }]
}
```

示例默认禁用，`.invalid` 与 TEST-NET 地址不是可直接部署的目的地。实际由操作者配置固定 HTTPS 地址、窄 CIDR、主控 billing token 和所需 CA；策略/token 建议 root `0600`，目录 `0700`。token 不进入 argv、stdin、stdout、错误日志或商品配置。

目的地通过原请求 `product.controller_id` 精确选已启用的 host profile。公开 `controllerapi.LoadPolicy/New` 只是现有安全 transport 的薄导出，没有另一套 HTTP client：DNS 全量结果必须属于允许 CIDR，选一个固定地址拨号、验证 TLS/主机名；无代理、重定向、压缩、HTTP/2 自动重拨或自动重试。

## 显式发送与只读查询

```sh
# prepared-request.json 必须来自调用方已持久保存的不可变订单快照。
# 由 root 在受保护的主机执行；不要重新生成 operation_id 或 order_id。
aster-billing-plugin send < prepared-request.json
aster-billing-plugin lookup < prepared-request.json
```

请求严格为原八字段：`protocol, operation_id, order_id, owner_ref, hostname, configuration_revision, configuration_sha256, product`。配置 digest 必须匹配 product；请求 digest 由原 `BytesAndDigest` 计算，不添加字段、不改序列化协议。POST 仅显式 `send`；`lookup` 只 GET 同一 operation，携带原 operation ID 与 request digest，不发送新任务。

正常 stdout **仅原六字段**：`protocol, operation_id, order_id, request_sha256, status, resource_id`。完整结果必须绑定原 operation、order、请求 digest：

- `accepted`：主控受理，不代表 VM 已运行。
- `succeeded`：主控返回完成且有资源 ID；适配器不据此改写财务服务或已付款记录。
- `rejected`：主控明确拒绝，没有资源 ID。
- timeout、断连、错误 TLS、重定向、不完整/额外/重复字段、错身份、未知状态：不输出结果，不算成功，不自动 resend。

退出码：`0` 是完整已绑定响应（包括 accepted/rejected），**不是资源成功或付款成功**；`2` 输入/参数/输出配置错误；`3` 结果未确认，仅保留原请求并 lookup；`4` 发送前无法打开固定控制器策略；`5` 网络子命令非 root。stderr 只有固定错误码，不回显 peer 错误、参数、路径或密钥。若结果输出中断，也按未确认处理。

## 测试及边界

```sh
go test ./plugins/billingconnector ./cmd/aster-billing-plugin
go test -c -o /private-or-root-owned-dir/connector.test ./plugins/billingconnector
# 在隔离 Linux 以 root 执行：仅 loopback TLS 假主控，无真实 VM/财务库。
/private-or-root-owned-dir/connector.test -test.v -test.run '^TestRootTLSConnector'
```

非 root 全量测试会明确跳过受保护文件 + 真实 TLS 集成用例，不把 skip 说成通过。root 测试覆盖真实公开 transport、稳定请求/六字段结果、代理禁用、重定向/丢 ACK/错绑定/坏 JSON 的拒绝及无自动重拨。它证明协议和传输边界，**不代表真实 VM、财务付款开通或生产部署验收**。
