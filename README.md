# 星屿云 · 云主控与 KVM 被控

面向自建云平台的虚拟机管理系统。主控提供管理台、权限、资源任务和审计；被控部署在计算宿主机上，通过 libvirt / QEMU / KVM 管理虚拟机，无需在客户虚拟机内安装代理。

采用 Go、MySQL、Vue 3 / TypeScript 和原生 systemd。可独立管理计算资源，也可通过资源插件与[财务系统](https://github.com/xiaoqiqixi/betteridcsys-backend)连接。

[使用文档](docs/README.md) · [管理 API](aster-cloud/docs/CONSOLE_API.md) · [下载预发布版](https://github.com/xiaoqiqixi/betteridcsys/releases/tag/cloud-v0.1.0-rc.1) · [问题反馈](https://github.com/xiaoqiqixi/betteridcsys-cloud/issues)

## 主要功能

| 模块 | 功能 |
| --- | --- |
| 管理台 | 管理员/操作员/只读/自定义权限、成员与会话、任务、审计 |
| 节点与实例 | 节点准入、维护、预设配置创建实例、电源操作、删除与运行样本 |
| 存储 | 停止态单系统盘快照和备份、普通网络实例的四阶段冷迁移 |
| VPC 与网络 | OVS、IPAM、VXLAN peer、跨节点配置、批准路由与显式恢复 |
| 公网管理 | IPv4 地址池、分配回收、SNAT/DNAT、普通网络直绑与 VPC 浮动 IP |
| 财务连接 | 商品资源配置、独立连接身份与资源任务；不共享财务数据库或客户会话 |

**当前为预发布软件。** 真实 KVM、跨节点物理网络和生产容量尚未验收；热迁移、HA、IPv6、完整安全组及受控 VNC 尚不支持。存储与迁移对网络模式有限制，使用前阅读[功能范围](aster-cloud/docs/ARCHITECTURE.md)。

## 运行环境

- Ubuntu 22.04 / 24.04 amd64，原生 systemd；暂不支持 Ubuntu26。
- 主控使用专用 MySQL 和可信 TLS；自带 HTTPS 服务与管理页面。
- 被控需要可用的 `/dev/kvm`、libvirt/QEMU、足够的内存和存储，以及已规划的宿主网络。
- 主控、财务和计算节点分别部署，不在财务数据库主机上试运行客户虚拟机。

## 一键安装

主控和被控各运行一条命令，进入交互安装向导。程序自动下载并核验安装文件；按提示填写配置，确认后准备依赖、安装和启动服务。**无需下载源码，不需要 Git、Go 或 Node.js。**

以下命令安装已发布的 **0.1.0-rc.1 预发布版**，适用于 Ubuntu 22.04 / 24.04 amd64。请分别在主控服务器和专用 KVM 宿主机运行，不要在财务数据库主机上安装被控。

### 安装主控

```sh
bash -o pipefail -c 'curl --fail --silent --show-error --proto "=https" --tlsv1.2 --connect-timeout 10 --max-time 60 --max-filesize 1048576 https://raw.githubusercontent.com/xiaoqiqixi/betteridcsys/8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e/aster-cloud/deploy/install/release_verify.py | sudo /usr/bin/python3 -I - controller'
```

向导配置管理地址、TLS、独立 MySQL 和首个管理员。可选择自动准备新的专用数据库，不复用财务库。

### 安装 KVM 被控

```sh
bash -o pipefail -c 'curl --fail --silent --show-error --proto "=https" --tlsv1.2 --connect-timeout 10 --max-time 60 --max-filesize 1048576 https://raw.githubusercontent.com/xiaoqiqixi/betteridcsys/8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e/aster-cloud/deploy/install/release_verify.py | sudo /usr/bin/python3 -I - node'
```

向导可自动准备 libvirt/QEMU；需提供节点身份、证书、已批准镜像和资源预算。被控不会接管已有虚拟机或自动修改物理上联。

两条命令都固定到已发布源码，不跟随可变 main。初始脚本依赖 HTTPS 和你对该固定版本的信任，后续安装器与资源包独立验签。向导要求明确确认安装/启动，不自动接受空输入。

[安装指南](docs/INSTALL.md) · [首次使用](aster-cloud/docs/GETTING_STARTED.md) · [版本说明与完整文件](https://github.com/xiaoqiqixi/betteridcsys/releases/tag/cloud-v0.1.0-rc.1)

## 使用与运维

- [主控入门](aster-cloud/docs/GETTING_STARTED.md) · [主控运维](aster-cloud/deploy/controller-OPERATIONS.md) · [被控运维](aster-cloud/NODE_README.md)
- [VPC、路由与恢复](aster-cloud/docs/NETWORK_MANAGEMENT.md) · [公网地址池](aster-cloud/docs/PUBLIC_IP_MANAGEMENT.md)
- [公网出口](aster-cloud/docs/PUBLIC_NAT_EGRESS.md) · [直绑与浮动 IP](aster-cloud/docs/VM_PUBLIC_IP_MANAGEMENT.md) · [入站规则](aster-cloud/docs/PUBLIC_INGRESS.md)
- [日志与审计](aster-cloud/docs/LOGGING.md) · [财务连接](aster-cloud/plugins/billingconnector/README.md)

## 开发与集成

[管理 API](aster-cloud/docs/CONSOLE_API.md) · [网络 API](aster-cloud/docs/NETWORK_API.md) · [开发文档](docs/development/README.md)

## 许可证

[Apache License 2.0](LICENSE)。
