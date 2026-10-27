# 统一安装入口验收

2026-10-27，入口源码 `92e484389a84312ab5b5f8d25688a93d7047926f`，文件 `aster-cloud/deploy/install/cloud.py`。
入口 SHA256：`5573783622f7ebea88c1c1bbc789a6533e30cf08c5ff8f210a21e7ad5e3eea01`。

## 实际执行

[公开下载任务 40497444837](https://github.com/xiaoqiqixi/betteridcsys-cloud/actions/runs/40497444837) **4/4 成功**。
Ubuntu22/24 × 主控/被控，均创建真实 controlling tty，运行统一入口，输入对应菜单数字，实际下载精确旧 bootstrap、验证真实发布者签名并运行认证后的生产安装器只读 plan。

每组提供三份独立 JSON：实际发布证明、平台/来源复核、菜单选择证明。菜单证明绑定入口摘要、角色和发布证明字节摘要，不能用普通单测菜单截图替代。四份 Actions ZIP 已重新完整下载并核对 API 大小/SHA256，核对 control source、发行 source、角色、实际平台和每个布尔状态。

| 平台 / 角色 | artifact ID | ZIP SHA256 |
| --- | --- | --- |
| Ubuntu22 主控 | 12731256425 | `10477072518e12c654585e97ba456e341f18e0dd38a98de9a21518608ab3951e` |
| Ubuntu22 被控 | 12730744760 | `b50387011b08cbddb7a2cd8a4c2abe2eb403ede8a7bc7114435cffbe3427bca3` |
| Ubuntu24 主控 | 12731076786 | `5a7365d8c16a1dc5e52943b3916b4aa25d9fb92170d29e2b425cfdbd37f3ee6d` |
| Ubuntu24 被控 | 12731990338 | `865c3798e1f4d3828323d1748ef83d4d7de2aab6a99afa4076796d0a4190d031` |

另外，六项实际 CLI/tty 测试覆盖两角色、退出、空白/非法输入、EOF、超长输入、无终端管道、显式自动化角色和禁止 apply/start/自定义 URL。Mac 沙箱内 `/dev/tty` 被拒，获准执行仅选择测试后全部通过；没有因此弱化生产终端要求。

## 证明范围

- 真实发行仍是旧仓库 `cloud-v0.1.0-rc.1`、Release425041579、source8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e，不是新云仓库首发。
- `host_apply=false`、`service_started=false`、`real_kvm_acceptance=false`。这里证明统一入口贯通真实验签与 plan，不证明实际主控部署、节点准入、VM 创建或主控迁移。
- 完整[同源 CI 40497444251](https://github.com/xiaoqiqixi/betteridcsys-cloud/actions/runs/40497444251)已核对 **11/11 成功**。两份原生报告与实库浏览器 ZIP 均重新下载、验证 API 大小/SHA256 后检查实际 JSON。Ubuntu22/24 原生报告证实真实 APT、systemd、libvirt 准备通过且宿主网络未变；明确 `tcg_only=true`、`kvm_ready=false`，不冒充真 KVM。浏览器使用真实 MySQL、严格 TLS，节点 RPC 为隔离替身。
- README 单入口固定到已验源码，不使用可变 main；旧两种角色 bootstrap 调用仍兼容，不修改旧标签、Release 正文或资产。
- 旧仓库不能删除，直至新发行、迁移消费端和旧实例升级门禁完成。完整主控搬家实现见[实施合同](INSTALL_AND_MIGRATION.md)，当前尚未交付。

## 同源完整 CI 证据

| 证据 | artifact ID | ZIP SHA256 |
| --- | --- | --- |
| Ubuntu22 原生 libvirt | 12732013324 | `b6f7d8992b5a3b72eb26378b2480426a603491edcb2912d2efc6501aa89b0409` |
| Ubuntu24 原生 libvirt | 12731672918 | `3e47293b3e9d048092f25718174ab7f0108dbe8715ab8ff44b989bb0d7e59431` |
| MySQL 网络及身份浏览器 | 12730873088 | `31aadf1cdee1176c4112ba4274f68570b122a05ac1456a744f1081c9eb585be9` |
