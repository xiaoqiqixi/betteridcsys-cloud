# 网络协调与恢复验收记录（2026-10-23）

本轮为 `main` 开发增量，不是 KVM 真机验收或正式生产发布。没有更改财务源码、金额、支付、币种、商品历史快照或原 `aster.controller/1` / `aster.node/2` 的创建字节合同；没有在财务测试服务器安装虚拟化组件。

## 本轮交付范围

- 独立全局 VPC / epoch 协议、MySQL schema 007、session/RBAC/CSRF 管理 API、mTLS 节点三阶段协调。
- 新建 VM 先在原事务中预留成员与原 IPAM 绑定，再通过全节点网络屏障，最后派发原创建；未知结果只读核对，不重复 POST。
- 实际编译固定 peer VXLAN、同 VPC 定向 ARP/IP 转发、双向 drop meter 和受限 gateway appliance 路由；新 VM seed/XML 设置 root 批准的 MTU/路由。
- 已成功 epoch 的后续漂移、部分阶段失败、丢 ACK、落后/空节点 head 采用新的全组恢复 epoch；原快照和 receipt 保留。错误配置通过新的完整 replacement 审批纠正，不能修改原绑定。
- 本地及集群 OVS 恢复保留完整原操作证据；新 node journal schema 4 completion 与整组结果一次 CAS/save。原任务本来成功、结果文件单独存在均不能冒充新恢复完成。
- 64 次终身限制改为完整持久 SHA 链归档；覆盖超过 64 次、重启、精确旧请求重放、冲突、缺失/损坏归档和持久化失败，不是删除记录或单纯扩大常量。

## 自动化门禁

最终本机 Go 全量 race：1817 个 PASS 事件、0 FAIL、48 个显式 SKIP 事件（含实库子例与无测试包事件，不等于 48 项独立测试）。Go vet、Linux amd64 静态编译通过；Vue typecheck/格式/545 项测试/build 通过。最终 Go govulncheck 与 npm audit 均未检出漏洞。实际终态以本轮提交对应的 [GitHub workflow](../../.github/workflows/cloud.yml) 记录为准，不能把本机跳过项算通过。

该 workflow 要求：

1. Ubuntu 22.04 / 24.04 Go race、vet、静态 binary 编译。
2. 独立原生 MySQL 实库：迁移重入/结构冲突、事务回滚、全节点屏障、RBAC/CSRF、丢 ACK/只读核对、原创建绑定不变及恢复。实库 job 不接受测试 skip；root TLS 与原生 parser 分别有独立强制入口。
3. Ubuntu 22.04 / 24.04 发行版 `ovs-ofctl`：解析**生产编译器输出**，接收并检查真实 meter OpenFlow wire bytes，含失败负控制。仅装 `openvswitch-common`，不启动系统 OVS 服务，不创建 bridge，不改宿主网络。
4. Vue 检查与依赖审计、Go vulnerability 扫描。

本机 macOS 无隔离 MySQL DSN、无 Linux OVS parser，相关测试明确 skip；受保护 root TLS 检查亦由 CI 原生隔离入口运行。fake RPC、命令 runner、逐包规则解释器及 TLS fixture 均不是实机网络证据。

## 未验收与明确边界

- 两台 Ubuntu22+ KVM/OVS 宿主真实创建、跨节点 ARP/IP、MTU、限速丢包精度、错 VNI/peer 注入、OVS/宿主重启及连续恢复，按用户要求延期。
- 网关 appliance 自身 forwarding/返回路径/NAT/公网、防火墙和 underlay 隔离/认证需要独立部署验收；不是本系统已自动提供的 NAT、DHCP 或动态路由服务。
- 已有 guest 的 MTU/路由不会静默重写；未知 VM/磁盘/迁移结果不能用网络恢复猜成成功。不存在或实际未启动的 pending create/start 仍拒绝伪完成。
- systemd/TLS 安装、整机备份恢复/升级回滚和长期容量压测尚需专门环境。没有本轮新管理 UI 视觉改动或新浏览器截图证据。
- 归档保留全部历史，打开时完整校验，有随历史增长的 I/O/内存成本和现有文件大小保护；并不代表无限容量。

部署入口及不可绕过的恢复约束见 [运维说明](../deploy/OVERLAY_OPERATIONS.md)。这些缺项未消除前，不应把 main 开发检查称为可直接接入真实客户的完整生产验收。
