# 云系统原生 MySQL 测试环境

仅供 CI 验证，不是面向用户的安装器。用户使用[主控 / 被控安装命令](../../../../README.md#一键安装)。

## 来源与独立性

通用测试工具取自财务后端提交 `8e3e8ca9623a438c709b0c5d6cb2b8f699a243cf`，[UPSTREAM.json](UPSTREAM.json)记录原文件与导入文件 SHA256。运行脚本、固定分发元数据和生命周期测试保持原字节；分发测试只去除了不属于云仓库的财务安装器、Nginx 检查，原检查仍留在财务后端。

没有引入财务服务端、财务数据库迁移、金额、支付或历史快照实现。云主控仍使用自己的 schema 和账户；财务协议 SDK 的独立来源校验不变。

## 执行边界

1. `prepare-cloud-runner.py` 只接受本云仓库、main、受支持事件的 GitHub 托管 Ubuntu22/24 amd64 环境，以普通 runner 账户运行。仅通过系统签名软件源准备固定运行库，不安装 MySQL/Nginx/libvirt 服务。
2. 在 runner 的临时目录内创建独占 0700 目录，并绑定仓库、提交和运行身份。清理只接受同一运行的所有权标记；不接受任意删除路径，不提权递归删除。
3. `mysql-native.sh` 使用固定 Oracle MySQL 8.4 分发信息，每个包先检查完整大小和 SHA256，再验证包身份和安全解包。只启动该目录中自有的 Unix Socket MySQL，不开放 TCP，不复用宿主数据库。
4. 被测命令不能使用继承的云测试 DSN，工作流显式移除 `ASTER_CLOUD_TEST_DSN`。通用环境再清除 MySQL 密码/配置覆盖，创建专用测试凭据，控制自有进程生命周期。
5. 实库任务运行真实 SQL 权限、race、root TLS 和完整云 Go 检查。四项 OVS/NAT 测试在独立专用任务执行，root TLS 测试单独提权执行；不允许其余测试静默跳过。
6. 浏览器任务构建实际管理台，连接 Go HTTPS 与真实 MySQL；只上传清单限定的截图和脱敏结果，不上传数据库、凭据、证书私钥或浏览器配置。

`test_mysql_native.py` 是使用模拟可执行程序的生命周期契约，不是实库证明；`test_mysql_distribution.py` 是离线元数据契约；`test_prepare_cloud_runner.py` 模拟 OS/APT 边界，不会在本机安装依赖。真实 MySQL、浏览器、原生 libvirt 和公开安装下载各有独立任务，不能互相替代。
