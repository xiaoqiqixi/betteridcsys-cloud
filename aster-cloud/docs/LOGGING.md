# 运行日志与审计查询

应用诊断、数据库审计、节点恢复 journal 是三种不同数据，不能混用。下面是开发代码和运维模板，不表示已在生产宿主安装或完成外部日志留存/告警验收。

## 一行 JSON 运行事件

主控和被控的入口把 stderr 设为统一 JSON logger；CLI 的正常 stdout 合同保持原样。仅记录白名单事件与类型受限字段：UTC时间、级别、component、操作/实例/节点标识、动作、记录状态、固定诊断码和 journal_write_confirmed。不输出请求正文、Cookie、CSRF/token、DSN、SSH钥匙、证书、fence、guest初始化数据、宿主路径、错误字符串或子进程 stdout/stderr。未知事件名/字段和嵌套属性丢弃或替换，不能通过日志字段开启“详细秘密模式”。

- `aster_controller_operation`：管理操作显式 dispatch/reconcile 的结果，包括 claim 前失败。reconcile 仍只读原节点任务，不因日志自动补发。
- `aster_controller_provisioning`：原财务开通链的显式 dispatch/reconcile；不记录金额、原请求或订单正文。
- `aster_controller_transfer`：后台转运任务的收尾。错误、sending或uncertain提升WARN，不当成功。
- `aster_node_operation` / `aster_node_storage_operation`：被控电源/存储动作。journal写入未确认时只在诊断中记录uncertain/WARN及`JOURNAL_WRITE_UNCONFIRMED`，不把执行器返回0宣传为持久成功；不会为记录日志修改实际journal或结果。
- `aster_service_starting` / `aster_service_stopped`：进程启动尝试与正常停止，**不是 readiness / guest 就绪证明**。
- `aster_command_failed`：命令失败，退出非零；不回显非法参数或受保护错误。正常`doctor/check`和认证接口仍提供各自的受限状态。
- `aster_http_transport_error`：Go HTTP/TLS层错误存在的事实。peer提供的原始错误文本、地址及证书内容不进入事件。

诊断日志是尽力交付，不替代数据库事务内审计，也不保证进程崩溃/磁盘满时每行都已落盘。没有新增HTTP正文抓取或全量访问日志。当前不实现外部日志外送、不可篡改归档或告警通道。

## 原生 journal 查询与限流

模板显式使用stdout/stderr→journal和固定SyslogIdentifier，每个unit设置30秒/1000行诊断限流，避免异常TLS流量淹没磁盘；超限会丢诊断行，**不会删SQL审计或恢复journal**。此配置见 [systemd 249 官方日志选项](https://www.freedesktop.org/software/systemd/man/249/systemd.exec.html#LogRateLimitIntervalSec=)。

```sh
# unit名按实际安装文件；不依赖宿主存在jq
journalctl -u controller-aster.service --since '1 hour ago' -o cat
journalctl -u node-aster-node.service --since '1 hour ago' -o cat
```

需要独立保留上限时，可先审核 `deploy/journald-aster-cloud.conf.example`，再由宿主管理员为这两个unit添加`LogNamespace=aster-cloud`并安装专用namespace配置。该模板默认14天/128MiB，满额由journald管理诊断日志；命令需相应加`journalctl --namespace=aster-cloud`。namespace由systemd独立管理，不使用全局`journalctl --vacuum-*`误删财务站日志。模板不自动安装、重启服务或修改全机journald配置；部署前须核对目标systemd及可用磁盘，见 [systemd 249 namespace说明](https://www.freedesktop.org/software/systemd/man/249/systemd.exec.html#LogNamespace=)。

## 审计的精确定位

管理台审计查询需要`audit.read`；事件类别、动作、操作者、对象及UTC时间范围按AND精确匹配，时间为`[from,until)`。每页固定100条，游标绑定筛选；改变条件必须回结果第一页。不支持任意SQL、正则或全表下载，也不会根据诊断日志生成审计事实。具体参数与迁移门槛见 [CONSOLE_API.md](CONSOLE_API.md)。

节点`journal.json`包含操作幂等、未知结果、IP占位、source fence与恢复信息。**绝不能按诊断日志轮转、截断、vacuum或手工删旧操作**；64MiB上限仍需单独监控与恢复方案。主控SQL审计本轮不自动清除；长期合规保留/归档策略仍需独立设计和验收。
