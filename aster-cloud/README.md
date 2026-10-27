# 星屿云主控与 KVM 被控

主控负责管理台、权限、资源任务和审计；被控通过 libvirt/QEMU/KVM 管理计算宿主上的虚拟机。完整介绍见[项目首页](../README.md)，操作指南见[使用文档](../docs/README.md)。

## 使用入口

[安装](deploy/install/README.md) · [首次使用](docs/GETTING_STARTED.md) · [主控运维](deploy/controller-OPERATIONS.md) · [被控运维](NODE_README.md)

## 功能与接口

[功能范围](docs/ARCHITECTURE.md) · [管理台 API](docs/CONSOLE_API.md) · [网络 API](docs/NETWORK_API.md) · [财务连接器](plugins/billingconnector/README.md)

## 开发与版本

[开发指南](../docs/development/README.md) · [变更记录](CHANGELOG.md) · [发行版本](https://github.com/xiaoqiqixi/betteridcsys-cloud/releases)

当前为预发布软件；真实 KVM、物理网络与生产容量尚未验收。数据库、节点 journal 和 fabric journal 必须与所用版本匹配，升级前保存完整备份；不能通过删除日志、回执或旧状态来绕过兼容检查。
